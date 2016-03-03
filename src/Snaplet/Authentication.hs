{-# LANGUAGE DeriveGeneric       #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE RecordWildCards     #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell     #-}
module Snaplet.Authentication
       (initAuthentication, Authentication, requireUser, withUser,
        module X, AuthConfig(..))
       where

import           Control.Lens
import           Control.Monad.CatchIO            hiding (Handler)
import           Control.Monad.IO.Class
import           Control.Monad.Reader
import qualified Control.Monad.State.Class        as State
import           Control.Monad.Trans.Class
import           Control.Monad.Trans.Either
import           Crypto.BCrypt
import           Data.Aeson.TH                    hiding (defaultOptions)
import           Data.ByteString
import qualified Data.Map                         as Map
import           Data.Monoid
import           Data.Text                        (Text, pack)
import           Data.Text.Encoding
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
import           Snap                             hiding (with)
import           Snap.CORS
import           Snaplet.Authentication.Exception
import           Snaplet.Authentication.Queries
import           Snaplet.Authentication.Schema    as X
import           Web.JWT                          as JWT hiding (header)

data AuthConfig =
  AuthConfig {_jwtSecretKey :: Text
             ,_hostname     :: Text
             ,_github       :: Github.Config}
makeLenses ''AuthConfig

data Authentication b =
  Authentication {_poolLens                  :: SnapletLens b ConnectionPool
                 ,_randomNumberGeneratorLens :: SnapletLens b RandomNumberGenerator
                 ,_authConfig                :: AuthConfig}
makeLenses ''Authentication

$(deriveJSON (dropPrefixJSONOptions "_") ''AuthConfig)

data AuthenticationOptions = AuthenticationOptions {_githubAuthentication :: String}
  deriving (Eq,Show,Generic)

$(deriveJSON (dropPrefixJSONOptions "_")
             ''AuthenticationOptions)

------------------------------------------------------------
-- TODO Move to config
sessionCookieName :: ByteString
sessionCookieName = "sessionId"

sessionIdName :: Text
sessionIdName = "accountId"

twoWeeks :: NominalDiffTime
twoWeeks = 60 * 60 * 24 * 7 * 2

------------------------------------------------------------

baseSessionCookie :: Cookie
baseSessionCookie =
  Cookie {cookieName = sessionCookieName
         ,cookieValue = ""
         ,cookieExpires = Nothing
         ,cookieDomain = Nothing
         ,cookiePath = Just "/"
         ,cookieSecure = True
         ,cookieHttpOnly = False}

makeSessionJSON :: Text -> Secret -> UUID -> JSON
makeSessionJSON currentHostname theSecret key =
  encodeSigned
    HS256
    theSecret
    (JWT.def {iss = stringOrURI currentHostname
             ,unregisteredClaims =
                Map.fromList [(sessionIdName,String (toText key))]})

makeSessionCookie :: Text -> Secret -> UTCTime -> UUID -> Cookie
makeSessionCookie currentHostname theSecret expires key =
  baseSessionCookie {cookieValue =
                       encodeUtf8 $
                       makeSessionJSON currentHostname theSecret key
                    ,cookieExpires = Just expires}

------------------------------------------------------------

getSecretKey :: Handler b (Authentication b) Secret
getSecretKey = secret <$> view (authConfig . jwtSecretKey)

readAuthToken :: Handler b (Authentication b) (Maybe UUID)
readAuthToken =
  do secretKey <- getSecretKey
     maybeCookie <- getCookie sessionCookieName
     return $
       do authenticationCookie <- maybeCookie
          verifiedToken <-
            decodeAndVerifySignature
              secretKey
              (decodeUtf8 $ cookieValue authenticationCookie)
          let theClaims = unregisteredClaims $ claims verifiedToken
          sessionId <- Map.lookup sessionIdName theClaims
          case sessionId of
            (String s) -> fromText s
            _ -> Nothing

removeAuthToken :: Handler b v ()
removeAuthToken =
  let old = UTCTime (ModifiedJulianDay 0) 0
  in modifyResponse . addResponseCookie $
     baseSessionCookie {cookieValue = ""
                       ,cookieExpires = Just old}

writeAuthToken :: UTCTime -> UUID -> Handler b (Authentication b) ()
writeAuthToken expires accountId =
  do secretKey <- getSecretKey
     currentHostname <- view (authConfig . hostname)
     modifyResponse $
       Snap.addResponseCookie (makeSessionCookie currentHostname secretKey expires accountId)

------------------------------------------------------------

-- TODO Replace uses of this code with this call.
getConnection :: Handler b (Authentication b) ConnectionPool
getConnection =
  do pool <- view poolLens
     connection <- Snap.withTop pool State.get
     return connection

githubLoginUrl :: Github.Config -> Text
githubLoginUrl config =
  Data.Text.pack $
  mconcat [view Github.authUrl config
          ,"?scope=user:email,read:org,admin:repo_hook,&client_id="
          ,view Github.clientId config]

githubLoginHandler :: Handler b (Authentication b) ()
githubLoginHandler =
  do githubConfig <- view (authConfig . github)
     redirect . encodeUtf8 $ githubLoginUrl githubConfig

upsertAccount :: Github.Config
              -> ConnectionPool
              -> UUID
              -> ByteString
              -> IO (UTCTime,Key Account)
upsertAccount githubConfig connection uuid code =
  do accessToken <-
       view Github.accessToken <$>
       Github.requestAccess githubConfig code
     user <- runReaderT Github.getUserDetails accessToken
     now <- getCurrentTime
     accountKey <-
       runSqlPersistMPool (createOrUpdateGithubUser uuid now accessToken user)
                          connection
     return (now,accountKey)

processGithubAccessToken :: Text -> ByteString -> Handler b (Authentication b) ()
processGithubAccessToken redirectTarget code =
  do githubConfig <- view (authConfig . github)
     connection <- getConnection
     randomNumberGenerator <- view randomNumberGeneratorLens
     uuid <- Snap.withTop randomNumberGenerator getRandom
     (now,accountKey) <-
       liftIO $ upsertAccount githubConfig connection uuid code
     logError $
       "Upserted account key: " <>
       (toStrictByteString . unAccountKey) accountKey
     writeAuthToken (addUTCTime twoWeeks now)
                    (unAccountKey accountKey)
     redirect $ encodeUtf8 redirectTarget

githubCallbackHandler :: Text -> Handler b (Authentication b) ()
githubCallbackHandler redirectTarget =
  method GET $
  requireParam "code" >>=
  processGithubAccessToken redirectTarget

------------------------------------------------------------

processUsernamePassword :: ByteString -> ByteString -> Handler b (Authentication b) ()
processUsernamePassword username password =
  do connection <- getConnection
     matchingAccount <-
       liftIO $
       runSqlPersistMPool (lookupByUsername (decodeUtf8 username))
                          connection
     case matchingAccount of
       Nothing -> unauthorized
       Just (account,accountUidpwd) ->
         -- Validate password.
         if validatePassword (encodeUtf8 (accountUidpwdPassword $ accountUidpwd))
                             password
            then do now <- liftIO getCurrentTime
                    writeAuthToken (addUTCTime twoWeeks now)
                                   (accountAccountId account)
                    writeJSON account
            else unauthorized

usernamePasswordLoginHandler :: Handler b (Authentication b) ()
usernamePasswordLoginHandler =
  method POST $
  do username <- requirePostParam "username"
     password <- requirePostParam "password"
     processUsernamePassword username password

------------------------------------------------------------
-- | Require that an authenticated AuthUser is present in the current session.
-- This function has no DB cost - only checks to see if the client has passed a valid auth token.
requireUser :: SnapletLens b (Authentication b)
              -> Handler b v a
              -> (Key Account -> Handler b v a)
              -> Handler b v a
requireUser aLens bad good =
  do authToken <- Snap.withTop aLens readAuthToken
     case authToken of
       Nothing -> bad
       Just t -> good (AccountKey t)

withUser :: SnapletLens b (Authentication b)
         -> (Maybe (Key Account) -> Handler b v a)
         -> Handler b v a
withUser aLens handler =
  do maybeKey <- Snap.withTop aLens readAuthToken
     handler (AccountKey <$> maybeKey)

------------------------------------------------------------

logoutHandler :: Handler b (Authentication b) ()
logoutHandler =
  do removeAuthToken
     redirect "/"

userDetailsHandler :: Handler b (Authentication b) ()
userDetailsHandler =
  method GET $
  do logError "Looking up user details."
     connection <- getConnection
     authToken <- readAuthToken
     logError $
       "Got auth token: " <>
       maybe "<none>" toStrictByteString authToken
     case authToken of
       Nothing -> removeAuthToken >> pass
       Just accountId ->
         do account <-
              liftIO $
              runSqlPersistMPool
                (Database.Persist.get $
                 AccountKey accountId)
                connection
            case account of
              Nothing ->
                throw AccountNotFound
              Just a -> writeJSON a


migrate
  :: ConnectionPool -> EitherT Text IO ConnectionPool
migrate pool =
  do lift $
       runSqlPersistMPool (runMigration migrateAccounts)
                          pool
     return pool

initAuthentication
  :: Text
  -> AuthConfig
  -> SnapletLens b ConnectionPool
  -> SnapletLens b RandomNumberGenerator
  -> SnapletInit b (Authentication b)
initAuthentication redirectTarget _authConfig _poolLens _randomNumberGeneratorLens =
  makeSnaplet "authentication" "Authentication Snaplet" Nothing $
  do addRoutes [("/login/uidpwd",usernamePasswordLoginHandler)
               ,("/login/github",githubLoginHandler)
               ,("/callback/github",githubCallbackHandler redirectTarget)
               ,("/logout",logoutHandler)
               ,("/status",userDetailsHandler)]
     _ <- Snap.withTop _poolLens $ addPostInitHook migrate
     wrapSite $ applyCORS defaultOptions
     return Authentication {..}
