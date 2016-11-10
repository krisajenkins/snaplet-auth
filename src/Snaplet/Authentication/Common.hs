{-# LANGUAGE DeriveGeneric       #-}
{-# LANGUAGE FlexibleContexts    #-}
{-# LANGUAGE OverloadedStrings   #-}
{-# LANGUAGE RecordWildCards     #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell     #-}

module Snaplet.Authentication.Common where

import           Control.Lens
import qualified Control.Monad.State.Class   as State
import           Data.Aeson.TH               hiding (defaultOptions)
import           Data.ByteString
import           Data.Text                   as T
import           Data.Time
import           Database.Esqueleto          hiding (migrate)
import           GHC.Generics
import           Kashmir.Aeson
import           Kashmir.Email
import qualified Kashmir.Github              as Github
import           Kashmir.Snap.Snaplet.Random
import           Snap
import           Web.JWT                     as JWT hiding (header)

twoHours :: NominalDiffTime
twoHours = 60 * 60 * 2

twoWeeks :: NominalDiffTime
twoWeeks = 60 * 60 * 24 * 7 * 2

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

getSecretKey :: Handler b (Authentication b) Secret
getSecretKey = secret <$> view (authConfig . jwtSecretKey)

getConnection :: Handler b (Authentication b) ConnectionPool
getConnection = do
    pool <- view poolLens
    Snap.withTop pool State.get
