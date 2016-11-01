{-# LANGUAGE DeriveGeneric       #-}
{-# LANGUAGE FlexibleContexts    #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE RecordWildCards     #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell     #-}

module Snaplet.Authentication
  ( initAuthentication
  , Authentication
  , requireUser
  , withUser
  , makeSessionJSON
  , sessionIdName
  , extractClaims
  , module Q
  , module X
  , AuthConfig(..)
  ) where

import           Control.Lens
import           Control.Monad.CatchIO            hiding (Handler)
import           Control.Monad.IO.Class
import           Control.Monad.Reader
import qualified Control.Monad.State.Class        as State
import           Control.Monad.Trans.Either
import           Control.Monad.Trans.Maybe
import           Crypto.BCrypt
import qualified Data.Aeson                       as Aeson
import           Data.Aeson.TH                    hiding (defaultOptions)
import           Data.ByteString
import qualified Data.Map                         as Map
import           Data.Monoid
import           Data.Text                        as T
import           Data.Text.Encoding
import qualified Data.Text.Lazy                   as LT
import           Data.Time
import           Data.UUID
import           Data.Yaml
import           Database.Esqueleto               hiding (migrate)
import qualified Database.Persist
import           GHC.Generics
import           Kashmir.Aeson
import qualified Kashmir.Github                   as Github
import           Kashmir.Snap.Snaplet.Random
import           Kashmir.Snap.Utils
import           Kashmir.UUID
import           Kashmir.Web
import           Network.Mail.Mime
import           Snap                             hiding (with)
import           Snap.CORS
import           Snaplet.Authentication.Exception
import           Snaplet.Authentication.Queries
import qualified Snaplet.Authentication.Queries   as Q (getGithubAccessToken)
import           Snaplet.Authentication.Schema    as X
import           Web.JWT                          as JWT hiding (header)

data AuthConfig = AuthConfig
    { _jwtSecretKey :: Text
    , _hostname     :: Text
    , _github       :: Github.Config
    }

makeLenses ''AuthConfig

data Authentication b = Authentication
    { _poolLens                  :: SnapletLens b ConnectionPool
    , _randomNumberGeneratorLens :: SnapletLens b RandomNumberGenerator
    , _authConfig                :: AuthConfig
    }

makeLenses ''Authentication

$(deriveJSON (dropPrefixJSONOptions "_") ''AuthConfig)

data AuthenticationOptions = AuthenticationOptions
    { _githubAuthentication :: String
    } deriving (Eq, Show, Generic)

$(deriveJSON (dropPrefixJSONOptions "_") ''AuthenticationOptions)

------------------------------------------------------------
-- TODO Move to config
sessionCookieName :: ByteString
sessionCookieName = "sessionId"

sessionIdName :: Text
sessionIdName = "accountId"

resetPasswordJWTKey :: Text
resetPasswordJWTKey = "ResetPassword"

twoWeeks :: NominalDiffTime
twoWeeks = 60 * 60 * 24 * 7 * 2

------------------------------------------------------------
baseSessionCookie :: Cookie
baseSessionCookie =
    Cookie
    { cookieName = sessionCookieName
    , cookieValue = ""
    , cookieExpires = Nothing
    , cookieDomain = Nothing
    , cookiePath = Just "/"
    , cookieSecure = True
    , cookieHttpOnly = False
    }

makeSessionJSON :: Text -> Secret -> UUID -> JSON
makeSessionJSON currentHostname theSecret key =
    encodeSigned
        HS256
        theSecret
        (JWT.def
         { iss = stringOrURI currentHostname
         , unregisteredClaims =
             Map.fromList [(sessionIdName, Aeson.String (toText key))]
         })

makePasswordResetJSON :: Text -> Secret -> UUID -> JSON
makePasswordResetJSON currentHostname theSecret key =
    encodeSigned
        HS256
        theSecret
        (JWT.def
         { iss = stringOrURI currentHostname
         , sub = stringOrURI (toText key)
         , unregisteredClaims =
             Map.fromList [(resetPasswordJWTKey, Aeson.Bool True)]
         })

makeSessionCookie :: Text -> Secret -> UTCTime -> UUID -> Cookie
makeSessionCookie currentHostname theSecret expires key =
    baseSessionCookie
    { cookieValue = encodeUtf8 $ makeSessionJSON currentHostname theSecret key
    , cookieExpires = Just expires
    }

------------------------------------------------------------

extractClaims :: Secret -> Text -> Maybe JWTClaimsSet
extractClaims secretKey rawText =
    claims <$> decodeAndVerifySignature secretKey rawText

------------------------------------------------------------

getSecretKey :: Handler b (Authentication b) Secret
getSecretKey = secret <$> view (authConfig . jwtSecretKey)

readAuthToken :: Handler b (Authentication b) (Maybe UUID)
readAuthToken = do
    secretKey <- getSecretKey
    maybeCookie <- getCookie sessionCookieName
    return $
        do authenticationCookie <- maybeCookie
           theClaims <-
               extractClaims
                   secretKey
                   (decodeUtf8 $ cookieValue authenticationCookie)
           sessionId <- Map.lookup sessionIdName (unregisteredClaims theClaims)
           case sessionId of
               (String s) -> fromText s
               _ -> Nothing

removeAuthToken
    :: MonadSnap m
    => m ()
removeAuthToken =
    let old = UTCTime (ModifiedJulianDay 0) 0
    in modifyResponse . addResponseCookie $
       baseSessionCookie
       { cookieValue = ""
       , cookieExpires = Just old
       }

writeAuthToken :: UTCTime -> UUID -> Handler b (Authentication b) ()
writeAuthToken expires accountId = do
    secretKey <- getSecretKey
    currentHostname <- view (authConfig . hostname)
    modifyResponse $
        Snap.addResponseCookie
            (makeSessionCookie currentHostname secretKey expires accountId)

------------------------------------------------------------
-- TODO Replace uses of this code with this call.
getConnection :: Handler b (Authentication b) ConnectionPool
getConnection = do
    pool <- view poolLens
    Snap.withTop pool State.get

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
processUsernamePassword :: ByteString
                        -> ByteString
                        -> Handler b (Authentication b) ()
processUsernamePassword username password = do
    connection <- getConnection
    matchingAccount <-
        liftIO $ runSqlPersistMPool (lookupByUsername (decodeUtf8 username)) connection
    case matchingAccount of
        Nothing -> unauthorized
        -- Validate password.
        Just (account, accountUidpwd) ->
            if validatePassword
                   (encodeUtf8 (accountUidpwdPassword accountUidpwd))
                   password
                then authorizedAccountResponse account
                else unauthorized

authorizedAccountResponse :: Account -> Handler b (Authentication b) ()
authorizedAccountResponse account = do
    now <- liftIO getCurrentTime
    writeAuthToken (addUTCTime twoWeeks now) (accountAccountId account)
    writeJSON account

usernamePasswordLoginHandler :: Handler b (Authentication b) ()
usernamePasswordLoginHandler =
    method POST $
    do username <- requirePostParam "username"
       password <- requirePostParam "password"
       processUsernamePassword username password

------------------------------------------------------------
data PasswordResetRequest = PasswordResetRequest
    { _username :: Text
    } deriving (Show, Eq)

makeLenses ''PasswordResetRequest
$(deriveJSON (dropPrefixJSONOptions "_") ''PasswordResetRequest)

usernamePasswordResetHandler :: Handler b (Authentication b) ()
usernamePasswordResetHandler =
    method POST $
    do secretKey <- getSecretKey
       passwordResetRequest <- requireBoundedJSON 1024
       connection <- getConnection
       currentHostname <- view (authConfig . hostname)
       maybeAccount <-
           liftIO $
           runSqlPersistMPool
               (lookupByUsername (view username passwordResetRequest))
               connection
       case maybeAccount of
           Nothing -> notfound
           Just (account, _) ->
               let resetToken =
                       makePasswordResetJSON
                           currentHostname
                           secretKey
                           (accountAccountId account)
                   mailFrom =
                       Address
                           (Just "CommercialStreet")
                           "noreply@commercialstreet.co.uk"
                   mailTo =
                       [Address (Just "Kris Jenkins") "krisajenkins@gmail.com"]
                   mailCc = []
                   mailBcc = []
                   mailHeaders = [("Subject", "Password Reset Requested")]
                   mailParts =
                       [[plainPart ("Hello\n" <> LT.fromStrict resetToken)]]
                   mail =
                       Mail
                       { ..
                       }
               in do liftIO $ sendmail =<< renderMail' mail
                     writeJSON (Map.fromList [("email_sent" :: Text, True)])

data PasswordResetCompletion = PasswordResetCompletion
    { _token       :: Text
    , _newPassword :: Text
    } deriving (Show, Eq)

makeLenses ''PasswordResetCompletion
$(deriveJSON (dropPrefixJSONOptions "_") ''PasswordResetCompletion)

usernamePasswordResetCompletionHandler :: Handler b (Authentication b) ()
usernamePasswordResetCompletionHandler =
    method POST $
    do secretKey <- getSecretKey
       passwordResetCompletion <- requireBoundedJSON 1024
       connection <- getConnection
       case (do theClaims <-
                    extractClaims secretKey (view token passwordResetCompletion)
                subject <- stringOrURIToText <$> JWT.sub theClaims
                uuid <- fromText subject
                isResetCompletion <-
                    Map.lookup
                        resetPasswordJWTKey
                        (unregisteredClaims theClaims)
                case isResetCompletion of
                    (Aeson.Bool True) -> Just uuid
                    _ -> Nothing) of
           Just uuid
           -- Verified!
            -> do
               maybeHashedPassword <-
                   liftIO $ hashFor (view newPassword passwordResetCompletion)
               case maybeHashedPassword of
                   Nothing -> unauthorized
                   Just hashedPassword -> do
                       maybeAccount <-
                           liftIO $
                           runSqlPersistMPool
                               (resetUidpwdUserPassword uuid hashedPassword)
                               connection
                       case maybeAccount of
                           Just account -> authorizedAccountResponse account
                           Nothing -> unauthorized
           Nothing -> unauthorized


------------------------------------------------------------
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

userDetailsHandler :: Handler b (Authentication b) ()
userDetailsHandler =
    method GET $
    do logError "Looking up user details."
       connection <- getConnection
       authToken <- readAuthToken
       logError $ "Got auth token: " <> maybe "<none>" toStrictByteString authToken
       case authToken of
           Nothing -> removeAuthToken >> pass
           Just accountId -> do
               account <-
                   liftIO $
                   runSqlPersistMPool
                       (Database.Persist.get $ AccountKey accountId)
                       connection
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
           [ ("/login/uidpwd", usernamePasswordLoginHandler)
           , ("/reset/uidpwd", usernamePasswordResetHandler)
           , ("/reset/uidpwd/complete", usernamePasswordResetCompletionHandler)
           , ("/login/github", githubLoginHandler)
           , ("/callback/github", githubCallbackHandler redirectTarget)
           , ("/logout", logoutHandler)
           , ("/status", userDetailsHandler)]
       _ <- Snap.withTop _poolLens $ addPostInitHook migrate
       wrapSite $ applyCORS defaultOptions
       return
           Authentication
           { ..
           }
