{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DefaultSignatures #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE EmptyDataDecls #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeFamilies #-}

module Snaplet.Authentication.Schema where

import Control.Lens (view)
import Control.Monad
import Control.Monad.IO.Class
import Crypto.BCrypt
import Data.Aeson.TH (deriveJSON)
import Data.Text hiding (head)
import Data.Text.Encoding
import Data.Time.Clock
import Database.Esqueleto
import Database.Persist.TH
import GHC.Generics (Generic)
import Kashmir.Aeson
import Kashmir.Database.Postgresql
import Snaplet.Authentication.Types
import Kashmir.Email
import Kashmir.Github as Github
import Kashmir.UUID
import Prelude hiding (id)

share
  [mkPersist sqlSettings, mkMigrate "migrateAccounts"]
  [persistLowerCase|
  Account
    accountId UUID sqltype=uuid
    created UTCTime
    Primary accountId
    deriving Read Show Eq Generic

  AccountUidpwd
    accountId UUID sqltype=uuid
    email Email sqltype=text
    password Text sqltype=text
    Primary email
    UniqueEmail email
    deriving Read Show Eq Generic

  AccountGithub
    githubUserLogin Text sqltype=text
    accountId AccountId sqltype=uuid
    accessToken AccessToken sqltype=text
    Primary accountId
    Unique GithubUserUnique githubUserLogin
    deriving Read Show Eq Generic
  |]

$(deriveJSON (dropPrefixJSONOptions "account") ''Account)

-- TODO Update more details.
createOrUpdateGithubUser :: UUID
                         -> UTCTime
                         -> AccessToken
                         -> GithubUser
                         -> SqlPersistM (Key Account)
createOrUpdateGithubUser uuid created theToken githubUser =
  let savepointName = "upsert_github"
  in do void $ createSavepoint savepointName
        accountKey <- insert $ Account uuid created
        maybeGithubKey <-
          insertUnlessDuplicate
            AccountGithub
            { accountGithubAccountId = accountKey
            , accountGithubGithubUserLogin = view githubUserLogin githubUser
            , accountGithubAccessToken = theToken
            }
        case maybeGithubKey of
          Just _ -> releaseSavepoint savepointName >> return accountKey
          Nothing -> do
            let match g =
                  where_
                    (g ^. AccountGithubGithubUserLogin ==.
                     val (view githubUserLogin githubUser))
            void $ rollbackToSavepoint savepointName
            update $ \g -> do
              set
                g
                [ AccountGithubAccessToken =. val theToken
                , AccountGithubGithubUserLogin =.
                  val (view githubUserLogin githubUser)
                ]
              match g
            accountIds <-
              select . from $ \g -> do
                match g
                return (g ^. AccountGithubAccountId)
            return . unValue . head $ accountIds

-- TODO This should handle failed inserts somehow.
createPasswordUser :: UUID
                   -> UTCTime
                   -> Registration
                   -> SqlPersistM (Maybe Account)
createPasswordUser uuid created payload = do
  Just hashedPassword <-
    liftIO $
    hashPasswordUsingPolicy
      fastBcryptHashingPolicy
      (encodeUtf8 (registrationPassword payload))
  let account = Account uuid created
  let accountUidpwd =
        AccountUidpwd
        { accountUidpwdAccountId = uuid
        , accountUidpwdEmail = registrationEmail payload
        , accountUidpwdPassword = decodeUtf8 hashedPassword
        }
  insertBy accountUidpwd >>= \case
    Left existingEntity -> return Nothing
    Right _ -> do
      _ <- insert account
      return $ Just account
