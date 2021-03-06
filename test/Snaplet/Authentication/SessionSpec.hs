{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}

module Snaplet.Authentication.SessionSpec where

import qualified Data.Aeson as Aeson
import qualified Data.Map as Map
import qualified Data.UUID as UUID
import Snaplet.Authentication.Session
import Test.Hspec
import qualified Web.JWT as JWT

spec :: Spec
spec = do
  makeSessionJSONSpec

makeSessionJSONSpec :: Spec
makeSessionJSONSpec =
  describe "makeSessionJSON" $ do
    it "should complete a two-way session encode" $
      (JWT.sub =<< theClaims) `shouldBe` (JWT.stringOrURI rawUUID)
  where
    rawUUID = "123e4567-e89b-12d3-a456-426655440000"
    Just uuid = UUID.fromText rawUUID
    secret = JWT.secret "ASDFASDFASDF"
    encoded = makeSessionJSON "www.somehost.com" secret uuid
    theClaims = extractClaims secret encoded
