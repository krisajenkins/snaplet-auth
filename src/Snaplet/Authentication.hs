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
import           Data.Time
import           Data.Time.Clock.POSIX
import           Data.UUID
import           Database.Esqueleto               hiding (migrate)
import qualified Database.Persist
import           GHC.Generics
import           Kashmir.Aeson
import           Kashmir.Email
import qualified Kashmir.Github                   as Github
import           Kashmir.Snap.Snaplet.Random
import           Kashmir.Snap.Utils
import           Kashmir.UUID
import           Kashmir.Web
import           Lucid
import           Network.Mail.Mime
import           Snap                             hiding (with)
import           Snap.CORS
import           Snaplet.Authentication.Exception
import           Snaplet.Authentication.Queries
import qualified Snaplet.Authentication.Queries   as Q (getGithubAccessToken)
import           Snaplet.Authentication.Schema    as X
import           Web.JWT                          as JWT hiding (header)

data AuthConfig = AuthConfig
    { _jwtSecretKey      :: Text
    , _hostname          :: Text
    , _github            :: Github.Config
    , _resetEmailName    :: Text
    , _resetEmail        :: Email
    , _resetEmailSubject :: Text
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
-- TODO Move this cookie name to Config.
sessionCookieName :: ByteString
sessionCookieName = "sessionId"

resetPasswordJWTKey :: Text
resetPasswordJWTKey = "ResetPassword"

twoHours :: NominalDiffTime
twoHours = 60 * 60 * 2

twoWeeks :: NominalDiffTime
twoWeeks = 60 * 60 * 24 * 7 * 2

------------------------------------------------------------
handleSql :: SqlPersistM a -> Handler b (Authentication b) a
handleSql sql = do
    connection <- getConnection
    liftIO $ runSqlPersistMPool sql connection

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

-- TODO Add an expiry time.
makeSessionJSON :: Text -> Secret -> UUID -> JSON
makeSessionJSON currentHostname theSecret uuid =
    encodeSigned
        HS256
        theSecret
        (JWT.def
         { iss = stringOrURI currentHostname
         , sub = stringOrURI $ toText uuid
         })

makePasswordResetJSON :: UTCTime -> Text -> Secret -> UUID -> JSON
makePasswordResetJSON now currentHostname theSecret uuid =
    encodeSigned
        HS256
        theSecret
        (JWT.def
         { iss = stringOrURI currentHostname
         , sub = stringOrURI (toText uuid)
         , JWT.exp = numericDate . utcTimeToPOSIXSeconds $ addUTCTime twoHours now
         , unregisteredClaims =
             Map.fromList [(resetPasswordJWTKey, Aeson.Bool True)]
         })

makeSessionCookie :: Text -> Secret -> UTCTime -> UUID -> Cookie
makeSessionCookie currentHostname theSecret expires uuid =
    baseSessionCookie
    { cookieValue = encodeUtf8 $ makeSessionJSON currentHostname theSecret uuid
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
           sessionId <- stringOrURIToText <$> sub theClaims
           fromText sessionId

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

authorizedAccountResponse :: Account -> Handler b (Authentication b) ()
authorizedAccountResponse account = do
    now <- liftIO getCurrentTime
    writeAuthToken (addUTCTime twoWeeks now) (accountAccountId account)
    writeJSON account

emailPasswordLoginHandler :: Handler b (Authentication b) ()
emailPasswordLoginHandler =
    method POST $
    do emailParam <- decodeUtf8 <$> requirePostParam "email"
       passwordParam <- requirePostParam "password"
       case parseEmail emailParam of
           Left err -> malformedRequest (encodeUtf8 err)
           Right email -> processEmailPassword email passwordParam

------------------------------------------------------------
-- TODO We must gather email addresses. We should probably just make the username an email addresses.
-- TODO Tidy
-- TODO Extract the email creation.
data PasswordResetRequest = PasswordResetRequest
    { _email        :: Email
    , _redirectHost :: Text
    , _redirectHash :: Text
    } deriving (Show, Eq)

makeLenses ''PasswordResetRequest

$(deriveJSON (dropPrefixJSONOptions "_") ''PasswordResetRequest)

emailPasswordResetHandler :: Handler b (Authentication b) ()
emailPasswordResetHandler =
    method POST $
    do secretKey <- getSecretKey
       passwordResetRequest <- requireBoundedJSON 1024
       currentHostname <- view (authConfig . hostname)
       maybeAccount <- handleSql . lookupByEmail $ view email passwordResetRequest
       config <- view authConfig
       now <- liftIO getCurrentTime
       case maybeAccount of
           Nothing -> notfound
           Just (account, accountUidpwd) ->
               let resetToken =
                       makePasswordResetJSON
                           now
                           currentHostname
                           secretKey
                           (accountAccountId account)
                   toAddress =
                       Address
                           Nothing
                           (unEmail (accountUidpwdEmail accountUidpwd))
                   mail =
                       makeResetEmail
                           config
                           toAddress
                           passwordResetRequest
                           resetToken
               in do liftIO $ sendmail =<< renderMail' mail
                     writeJSON (Map.fromList [("email_sent" :: Text, True)])

makeResetEmail :: AuthConfig -> Address -> PasswordResetRequest -> Text -> Mail
makeResetEmail config toAddress passwordResetRequest resetToken =
    Mail
    { ..
    }
  where
    mailFrom =
        Address
            (Just (view resetEmailName config))
            (unEmail (view resetEmail config))
    mailTo = [toAddress]
    mailCc = []
    mailBcc = []
    mailHeaders = [("Subject", view resetEmailSubject config)]
    mailParts = [[htmlPart . renderText $ resetEmailBody passwordResetRequest resetToken]]

resetEmailBody :: PasswordResetRequest -> Text -> Html ()
resetEmailBody request resetToken =
    div_
        (do p_ "Hello,"
            p_
                (do "We have received a request to reset your password. Please "
                    a_
                        [ href_
                              (view redirectHost request <> "/?token=" <> resetToken <>
                               view redirectHash request)]
                        "visit this link"
                    " to complete the process.")
            p_ "Thank you.")

data PasswordResetCompletion = PasswordResetCompletion
    { _token       :: Text
    , _newPassword :: Text
    } deriving (Show, Eq)

makeLenses ''PasswordResetCompletion

$(deriveJSON (dropPrefixJSONOptions "_") ''PasswordResetCompletion)

extractVerifiedResetUUID :: Secret -> PasswordResetCompletion -> Maybe UUID
extractVerifiedResetUUID secretKey passwordResetCompletion =
    do theClaims <- extractClaims secretKey (view token passwordResetCompletion)
       subject <- stringOrURIToText <$> JWT.sub theClaims
       uuid <- fromText subject
       isResetCompletion <-
           Map.lookup resetPasswordJWTKey (unregisteredClaims theClaims)
       case isResetCompletion of
           (Aeson.Bool True) -> Just uuid
           _ -> Nothing

hashRequestedPassword
    :: MonadIO m
    => PasswordResetCompletion -> m (Maybe HashedPassword)
hashRequestedPassword = liftIO . hashFor . view newPassword

runResetPassword :: UUID
                 -> HashedPassword
                 -> Handler b (Authentication b) (Maybe Account)
runResetPassword uuid = handleSql . resetUidpwdUserPassword uuid

-- TODO This trio of MaybeT calls is suspicious.
processPasswordResetCompletion :: Handler b (Authentication b) (Maybe Account)
processPasswordResetCompletion = do
    secretKey <- getSecretKey
    passwordResetCompletion <- requireBoundedJSON 1024
    runMaybeT $
        do uuid <- MaybeT . pure $ extractVerifiedResetUUID secretKey passwordResetCompletion
           hashedPassword <-
               MaybeT (hashRequestedPassword passwordResetCompletion)
           MaybeT (runResetPassword uuid hashedPassword)

emailPasswordResetCompletionHandler :: Handler b (Authentication b) ()
emailPasswordResetCompletionHandler =
    method POST $
    do maybeAccount <- processPasswordResetCompletion
       case maybeAccount of
           Just account -> authorizedAccountResponse account
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
           , ("/status", userDetailsHandler)]
       _ <- Snap.withTop _poolLens $ addPostInitHook migrate
       wrapSite $ applyCORS defaultOptions
       return
           Authentication
           { ..
           }
