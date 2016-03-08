{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE DefaultSignatures          #-}
{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE EmptyDataDecls             #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GADTs                      #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE QuasiQuotes                #-}
{-# LANGUAGE TemplateHaskell            #-}
{-# LANGUAGE TypeFamilies               #-}

module Snaplet.Authentication.Schema where

import           Control.Lens                (view)
import           Control.Monad
import           Control.Monad.IO.Class
import           Crypto.BCrypt
import           Data.Aeson.TH               (deriveJSON)
import           Data.Text                   hiding (head)
import           Data.Text.Encoding
import           Data.Time.Clock
import           Database.Esqueleto
import           Database.Persist.TH
import           GHC.Generics                (Generic)
import           Kashmir.Aeson
import           Kashmir.Database.Postgresql
import           Kashmir.Email
import           Kashmir.Github              as Github
import           Kashmir.Github.Types.User   as GU
import           Kashmir.UUID
import           Prelude                     hiding (id)

share [mkPersist sqlSettings,mkMigrate "migrateAccounts"]
      [persistLowerCase|
  Account
    accountId UUID sqltype=uuid
    created UTCTime
    Primary accountId
    deriving Read Show Eq Generic

  AccountUidpwd
    accountId UUID sqltype=uuid
    username Text sqltype=text
    password Text sqltype=text
    Primary username
    deriving Read Show Eq Generic

  AccountGithub
    githubId Int
    accountId AccountId sqltype=uuid
    login Text
    email Email
    blog Text Maybe
    accessToken AccessToken sqltype=text
    Primary githubId
    Unique AccountIdUnique accountId
    deriving Read Show Eq Generic
  |]

$(deriveJSON (dropPrefixJSONOptions "account")
             ''Account)

-- TODO Update more details.
createOrUpdateGithubUser :: UUID -> UTCTime -> AccessToken -> GU.User -> SqlPersistM (Key Account)
createOrUpdateGithubUser uuid created theToken githubUser =
  let savepointName = "upsert_github"
  in do void $ createSavepoint savepointName
        accountKey <- insert $ Account uuid created
        maybeGithubKey <-
          insertUnlessDuplicate
            AccountGithub {accountGithubGithubId = GU._githubUserId githubUser
                          ,accountGithubAccountId = accountKey
                          ,accountGithubAccessToken = theToken
                          ,accountGithubLogin = view login githubUser
                          ,accountGithubBlog = view blog githubUser
                          ,accountGithubEmail = view email githubUser}
        case maybeGithubKey of
          Just _ -> releaseSavepoint savepointName >> return accountKey
          Nothing ->
            do let match g =
                     where_ (g ^. AccountGithubGithubId ==.
                             val (view githubUserId githubUser))
               void $ rollbackToSavepoint savepointName
               update $
                 \g ->
                   do set g
                          [AccountGithubAccessToken =. val theToken
                          ,AccountGithubBlog =. val (view blog githubUser)
                          ,AccountGithubEmail =. val (view email githubUser)
                          ,AccountGithubLogin =. val (view login githubUser)]
                      match g
               accountIds <-
                 select . from $
                 \g ->
                   do match g
                      return (g ^. AccountGithubAccountId)
               return . unValue . head $ accountIds

createPasswordUser :: UUID -> UTCTime -> Text -> Text -> SqlPersistM (Key Account)
createPasswordUser uuid created username password =
  do Just hashedPassword <-
       liftIO $
       hashPasswordUsingPolicy fastBcryptHashingPolicy
                               (encodeUtf8 password)
     accountKey <- insert $ Account uuid created
     _ <-
       insert AccountUidpwd {accountUidpwdAccountId = unAccountKey accountKey
                            ,accountUidpwdUsername = username
                            ,accountUidpwdPassword = decodeUtf8 hashedPassword}
     return accountKey
