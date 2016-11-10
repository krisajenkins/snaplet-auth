{-# LANGUAGE DeriveGeneric       #-}
{-# LANGUAGE FlexibleContexts    #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE RecordWildCards     #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell     #-}

module Snaplet.Authentication.PasswordReset
  ( emailPasswordResetHandler
  , emailPasswordResetCompletionHandler
  ) where

import           Control.Lens
import           Control.Monad.IO.Class
import           Control.Monad.Trans.Maybe
import qualified Data.Aeson                     as Aeson
import           Data.Aeson.TH                  hiding (defaultOptions)
import qualified Data.Map                       as Map
import           Data.Monoid
import           Data.Text                      as T
import           Data.Time
import           Data.Time.Clock.POSIX
import           Data.UUID
import           Kashmir.Aeson
import           Kashmir.Email
import           Kashmir.Snap.Utils
import           Kashmir.Web
import           Lucid
import           Network.Mail.Mime
import           Snap                           hiding (with)
import           Snaplet.Authentication.Common
import           Snaplet.Authentication.Queries
import           Snaplet.Authentication.Schema  as X
import           Snaplet.Authentication.Session
import           Web.JWT                        as JWT hiding (header)

resetPasswordJWTKey :: Text
resetPasswordJWTKey = "ResetPassword"

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
                   mail = makeResetEmail config toAddress passwordResetRequest resetToken
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
    mailParts =
        [ [ htmlPart . renderText $ resetEmailBody passwordResetRequest resetToken]]

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
extractVerifiedResetUUID secretKey passwordResetCompletion = do
    theClaims <- extractClaims secretKey (view token passwordResetCompletion)
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

------------------------------------------------------------
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

------------------------------------------------------------
emailPasswordResetCompletionHandler :: Handler b (Authentication b) ()
emailPasswordResetCompletionHandler =
    method POST $
    do maybeAccount <- processPasswordResetCompletion
       case maybeAccount of
           Just account -> authorizedAccountResponse account
           Nothing -> unauthorized
