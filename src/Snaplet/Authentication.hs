{-# LANGUAGE FlexibleContexts    #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE RecordWildCards     #-}
{-# LANGUAGE ScopedTypeVariables #-}

module Snaplet.Authentication
  ( initAuthentication
  , Authentication
  , requireUser
  , withUser
  , makeSessionJSON
  , module Snaplet.Authentication.Queries
  , module Snaplet.Authentication.Schema
  , AuthConfig(..)
  ) where

import           Control.Lens
import           Control.Monad.CatchIO                hiding (Handler)
import           Control.Monad.IO.Class
import           Control.Monad.Reader
import           Control.Monad.Trans.Either
import           Crypto.BCrypt
import           Data.ByteString
import           Data.Monoid
import           Data.Text                            as T
import           Data.Text.Encoding
import           Data.Time
import           Data.UUID
import           Database.Esqueleto                   hiding (migrate)
import qualified Database.Persist
import           Kashmir.Email
import qualified Kashmir.Github                       as Github
import           Kashmir.Snap.Snaplet.Random
import           Kashmir.Snap.Utils
import           Kashmir.UUID
import           Kashmir.Web
import           Snap                                 hiding (with)
import           Snaplet.Authentication.Common
import           Snaplet.Authentication.Exception
import           Snaplet.Authentication.PasswordReset
import           Snaplet.Authentication.Queries
import qualified Snaplet.Authentication.Queries       (getGithubAccessToken)
import           Snaplet.Authentication.Schema
import           Snaplet.Authentication.Session

------------------------------------------------------------

githubLoginUrl :: Github.Config -> Text
githubLoginUrl config =
    T.pack $
    mconcat
        [ view Github.authUrl config
        , "?scope=user:email,read:org,admin:repo_hook,&client_id="
        , view Github.clientId config]

githubLoginHandler :: Handler b (Authentication b) ()
githubLoginHandler = do
    githubConfig <- view (authConfig . github)
    redirect . encodeUtf8 $ githubLoginUrl githubConfig

upsertAccount
    :: Github.Config
    -> ConnectionPool
    -> UUID
    -> ByteString
    -> IO (UTCTime, Key Account)
upsertAccount githubConfig connection uuid code = do
    accessToken <-
        view Github.accessToken <$> Github.requestAccess githubConfig code
    user <- runReaderT Github.getUserDetails accessToken
    now <- getCurrentTime
    accountKey <-
        runSqlPersistMPool
            (createOrUpdateGithubUser uuid now accessToken user)
            connection
    return (now, accountKey)

processGithubAccessToken :: Text -> ByteString -> Handler b (Authentication b) ()
processGithubAccessToken redirectTarget code = do
    githubConfig <- view (authConfig . github)
    connection <- getConnection
    randomNumberGenerator <- view randomNumberGeneratorLens
    uuid <- Snap.withTop randomNumberGenerator getRandom
    (now, accountKey) <- liftIO $ upsertAccount githubConfig connection uuid code
    logError $ "Upserted account key: " <> (toStrictByteString . unAccountKey) accountKey
    writeAuthToken (addUTCTime twoWeeks now) (unAccountKey accountKey)
    redirect $ encodeUtf8 redirectTarget

githubCallbackHandler :: Text -> Handler b (Authentication b) ()
githubCallbackHandler redirectTarget =
    method GET $ requireParam "code" >>= processGithubAccessToken redirectTarget

------------------------------------------------------------
processEmailPassword :: Email -> ByteString -> Handler b (Authentication b) ()
processEmailPassword email password = do
    matchingAccount <- handleSql (lookupByEmail email)
    case matchingAccount of
        Nothing -> unauthorized
        -- Validate password.
        Just (account, accountUidpwd) ->
            if validatePassword
                   (encodeUtf8 (accountUidpwdPassword accountUidpwd))
                   password
                then authorizedAccountResponse account
                else unauthorized

emailPasswordLoginHandler :: Handler b (Authentication b) ()
emailPasswordLoginHandler =
    method POST $
    do emailParam <- decodeUtf8 <$> requirePostParam "email"
       passwordParam <- requirePostParam "password"
       case parseEmail emailParam of
           Left err -> malformedRequest (encodeUtf8 err)
           Right email -> processEmailPassword email passwordParam


-- | Require that an authenticated AuthUser is present in the current session.
-- This function has no DB cost - only checks to see if the client has passed a valid auth token.
requireUser
    :: SnapletLens b (Authentication b)
    -> Handler b v a
    -> (Key Account -> Handler b v a)
    -> Handler b v a
requireUser aLens bad good = do
    authToken <- Snap.withTop aLens readAuthToken
    case authToken of
        Nothing -> bad
        Just t -> good (AccountKey t)

withUser
    :: SnapletLens b (Authentication b)
    -> (Maybe (Key Account) -> Handler b v a)
    -> Handler b v a
withUser aLens handler = do
    maybeKey <- Snap.withTop aLens readAuthToken
    handler (AccountKey <$> maybeKey)

------------------------------------------------------------
logoutHandler
    :: MonadSnap m
    => m ()
logoutHandler = do
    removeAuthToken
    redirect "/"

authStatusHandler :: Handler b (Authentication b) ()
authStatusHandler =
    method GET $
    do logError "Looking up user details."
       authToken <- readAuthToken
       logError $ "Got auth token: " <> maybe "<none>" toStrictByteString authToken
       case authToken of
           Nothing -> removeAuthToken >> pass
           Just accountId -> do
               account <-
                   handleSql (Database.Persist.get $ AccountKey accountId)
               case account of
                   Nothing -> throw AccountNotFound
                   Just a -> writeJSON a

migrate :: ConnectionPool -> EitherT Text IO ConnectionPool
migrate pool = do
    lift $ runSqlPersistMPool (runMigration migrateAccounts) pool
    return pool

initAuthentication
    :: Text
    -> AuthConfig
    -> SnapletLens b ConnectionPool
    -> SnapletLens b RandomNumberGenerator
    -> SnapletInit b (Authentication b)
initAuthentication redirectTarget _authConfig _poolLens _randomNumberGeneratorLens =
    makeSnaplet "authentication" "Authentication Snaplet" Nothing $
    do addRoutes
           [ ("/login/uidpwd", emailPasswordLoginHandler)
           , ("/reset/uidpwd", emailPasswordResetHandler)
           , ("/reset/uidpwd/complete", emailPasswordResetCompletionHandler)
           , ("/login/github", githubLoginHandler)
           , ("/callback/github", githubCallbackHandler redirectTarget)
           , ("/logout", logoutHandler)
           , ("/status", authStatusHandler)]
       _ <- Snap.withTop _poolLens $ addPostInitHook migrate
       return
           Authentication
           { ..
           }
