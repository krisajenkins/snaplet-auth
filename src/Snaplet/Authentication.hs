{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
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

import Control.Lens
import Control.Monad.CatchIO hiding (Handler)
import Control.Monad.IO.Class
import Control.Monad.Reader
import Control.Monad.Trans.Either
import Crypto.BCrypt
import Data.ByteString
import Data.Monoid
import Data.Text as T
import Data.Text.Encoding
import Data.Time
import Data.UUID
import Database.Esqueleto hiding (migrate)
import qualified Database.Persist
import qualified Kashmir.Github as Github
import Kashmir.Snap.Snaplet.Random
import Kashmir.Snap.Utils
import Kashmir.UUID
import Kashmir.Web
import Snap hiding (with)
import Snaplet.Authentication.Common
import Snaplet.Authentication.Exception
import Snaplet.Authentication.PasswordReset
import Snaplet.Authentication.Queries
import Snaplet.Authentication.Schema
import Snaplet.Authentication.Session
import Snaplet.Authentication.Types

------------------------------------------------------------
githubLoginUrl :: Github.Config -> Text
githubLoginUrl config =
  T.pack $
  mconcat
    [ view Github.authUrl config
    , "?scope=user:email,read:org,admin:repo_hook,&client_id="
    , view Github.clientId config
    ]

githubLoginHandler :: Handler b (Authentication b) ()
githubLoginHandler = do
  githubConfig <- view (authConfig . github)
  redirect . encodeUtf8 $ githubLoginUrl githubConfig

upsertAccountFromGithub
  :: Github.Config
  -> ByteString
  -> UUID
  -> ConnectionPool
  -> IO (UTCTime, Key Account)
upsertAccountFromGithub githubConfig code uuid connection = do
  accessToken <-
    view Github.accessToken <$> Github.requestAccess githubConfig code
  user <- runReaderT Github.getUserDetails accessToken
  now <- getCurrentTime
  accountKey <-
    runSqlPersistMPool
      (createOrUpdateGithubUser uuid now accessToken user)
      connection
  return (now, accountKey)

processGithubAccessToken :: Text
                         -> ByteString
                         -> Handler b (Authentication b) ()
processGithubAccessToken redirectTarget code = do
  githubConfig <- view (authConfig . github)
  connection <- getConnection
  randomNumberGenerator <- view randomNumberGeneratorLens
  uuid <- Snap.withTop randomNumberGenerator getRandom
  (now, accountKey) <-
    liftIO $ upsertAccountFromGithub githubConfig code uuid connection
  logError $
    "Upserted account key: " <> (toStrictByteString . unAccountKey) accountKey
  writeAuthToken (addUTCTime twoWeeks now) (unAccountKey accountKey)
  redirect $ encodeUtf8 redirectTarget

githubCallbackHandler :: Text -> Handler b (Authentication b) ()
githubCallbackHandler redirectTarget =
  method GET $ requireParam "code" >>= processGithubAccessToken redirectTarget

------------------------------------------------------------
registrationHandler ::  Handler b (Authentication b) ()
registrationHandler =
  method POST $ do
    payload <- requireBoundedJSON 1024
    connection <- getConnection
    randomNumberGenerator <- view randomNumberGeneratorLens
    uuid <- Snap.withTop randomNumberGenerator getRandom
    maybeAccount <- liftIO $ createPasswordAccount payload uuid connection
    case maybeAccount of
      Nothing -> handleErrorWithMessage 409 "Conflict"
      Just account -> do
        logError $ "Created account: " <> encodeUtf8 (T.pack (show account))
        authorizedAccountResponse account

createPasswordAccount :: Registration
                      -> UUID
                      -> ConnectionPool
                      -> IO (Maybe Account)
createPasswordAccount payload uuid connection = do
  now <- getCurrentTime
  runSqlPersistMPool (createPasswordUser uuid now payload) connection

------------------------------------------------------------
processEmailPassword :: Login -> Handler b (Authentication b) ()
processEmailPassword payload = do
  matchingAccount <- handleSql (lookupByEmail (loginEmail payload))
  case matchingAccount of
    Nothing -> unauthorized
        -- Validate password.
    Just (account, accountUidpwd) ->
      if validatePassword
           (encodeUtf8 (accountUidpwdPassword accountUidpwd))
           (encodeUtf8 (loginPassword payload))
        then authorizedAccountResponse account
        else unauthorized

emailPasswordLoginHandler :: Handler b (Authentication b) ()
emailPasswordLoginHandler =
  method POST $ do
    payload <- requireBoundedJSON 1024
    matchingAccount <- handleSql (lookupByEmail (loginEmail payload))
    case matchingAccount of
      Nothing -> unauthorized
          -- Validate password.
      Just (account, accountUidpwd) ->
        if validatePassword
             (encodeUtf8 (accountUidpwdPassword accountUidpwd))
             (encodeUtf8 (loginPassword payload))
          then authorizedAccountResponse account
          else unauthorized

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
  method GET $ do
    logError "Looking up user details."
    authToken <- readAuthToken
    logError $ "Got auth token: " <> maybe "<none>" toStrictByteString authToken
    case authToken of
      Nothing -> removeAuthToken >> pass
      Just accountId -> do
        account <- handleSql (Database.Persist.get $ AccountKey accountId)
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
  makeSnaplet "authentication" "Authentication Snaplet" Nothing $ do
    addRoutes
      [ ("/login/uidpwd", emailPasswordLoginHandler)
      , ("/registration/uidpwd", registrationHandler)
      , ("/reset/uidpwd", emailPasswordResetHandler)
      , ("/reset/uidpwd/complete", emailPasswordResetCompletionHandler)
      , ("/login/github", githubLoginHandler)
      , ("/callback/github", githubCallbackHandler redirectTarget)
      , ("/logout", logoutHandler)
      , ("/status", authStatusHandler)
      ]
    _ <- Snap.withTop _poolLens $ addPostInitHook migrate
    return Authentication {..}
