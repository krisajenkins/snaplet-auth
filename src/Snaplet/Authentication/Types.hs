{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}

module Snaplet.Authentication.Types where

import Data.Aeson
import Data.Aeson.Casing
import Data.Text hiding (head)
import GHC.Generics (Generic)
import Kashmir.Email

data Registration = Registration
  { registrationEmail :: Email
  , registrationPassword :: Text
  } deriving (Show, Eq, Generic)

instance ToJSON Registration where
   toJSON = genericToJSON $ aesonPrefix snakeCase

instance FromJSON Registration where
   parseJSON = genericParseJSON $ aesonPrefix snakeCase

------------------------------------------------------------

data Login = Login
  { loginEmail :: Email
  , loginPassword :: Text
  } deriving (Show, Eq, Generic)

instance ToJSON Login where
   toJSON = genericToJSON $ aesonPrefix snakeCase

instance FromJSON Login where
   parseJSON = genericParseJSON $ aesonPrefix snakeCase
