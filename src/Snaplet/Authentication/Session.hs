{-# LANGUAGE OverloadedStrings #-}

module Snaplet.Authentication.Session where

import Control.Lens
import Control.Monad.IO.Class
import Data.Text
import Data.Text.Encoding
import Data.Time
import Kashmir.UUID
import Kashmir.Web
import Snap
import Snaplet.Authentication.Common
import Snaplet.Authentication.Schema
import Web.JWT as JWT hiding (header)

extractClaims :: Secret -> Text -> Maybe JWTClaimsSet
extractClaims secretKey rawText =
  claims <$> decodeAndVerifySignature secretKey rawText

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
     {iss = stringOrURI currentHostname, sub = stringOrURI $ toText uuid})

makeSessionCookie :: Text -> Secret -> UTCTime -> UUID -> Cookie
makeSessionCookie currentHostname theSecret expires uuid =
  baseSessionCookie
  { cookieValue = encodeUtf8 $ makeSessionJSON currentHostname theSecret uuid
  , cookieExpires = Just expires
  }

------------------------------------------------------------
readAuthToken :: Handler b (Authentication b) (Maybe UUID)
readAuthToken = do
  secretKey <- getSecretKey
  maybeCookie <- getCookie sessionCookieName
  return $ do
    authenticationCookie <- maybeCookie
    theClaims <-
      extractClaims secretKey (decodeUtf8 $ cookieValue authenticationCookie)
    sessionId <- stringOrURIToText <$> sub theClaims
    fromText sessionId

writeAuthToken :: UTCTime -> UUID -> Handler b (Authentication b) ()
writeAuthToken expires accountId = do
  secretKey <- getSecretKey
  currentHostname <- view (authConfig . hostname)
  modifyResponse $
    Snap.addResponseCookie
      (makeSessionCookie currentHostname secretKey expires accountId)

removeAuthToken
  :: MonadSnap m
  => m ()
removeAuthToken =
  let old = UTCTime (ModifiedJulianDay 0) 0
  in modifyResponse . addResponseCookie $
     baseSessionCookie {cookieValue = "", cookieExpires = Just old}

------------------------------------------------------------
authorizedAccountResponse :: Account -> Handler b (Authentication b) ()
authorizedAccountResponse account = do
  now <- liftIO getCurrentTime
  writeAuthToken (addUTCTime twoWeeks now) (accountAccountId account)
  writeJSON account
