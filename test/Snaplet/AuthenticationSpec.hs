{-# LANGUAGE DeriveAnyClass    #-}
{-# LANGUAGE DeriveGeneric     #-}
{-# LANGUAGE OverloadedStrings #-}

module Snaplet.AuthenticationSpec where

-- import           Data.Char
import qualified Data.Map               as Map
-- import           Data.Monoid
-- import           Data.Proxy
-- import           Data.Text              hiding (unlines)
-- import           Data.Time
import qualified Data.Aeson             as Aeson
import qualified Data.UUID              as UUID
import           Snaplet.Authentication
import           Test.Hspec
import qualified Web.JWT                as JWT

spec :: Spec
spec =
  do makeSessionJSONSpec

makeSessionJSONSpec :: Spec
makeSessionJSONSpec =
    describe "makeSessionJSON" $
    do it "should complete a two-way session encode" $
           theClaims `shouldBe`
           Just (Map.fromList [(sessionIdName, Aeson.String rawUUID)])
  where
    rawUUID = "123e4567-e89b-12d3-a456-426655440000"
    Just uuid = UUID.fromText rawUUID
    secret = JWT.secret "ASDFASDFASDF"
    encoded = makeSessionJSON "SomeHost" secret uuid
    decoded = JWT.decodeAndVerifySignature secret encoded
    theClaims = JWT.unregisteredClaims . JWT.claims <$> decoded