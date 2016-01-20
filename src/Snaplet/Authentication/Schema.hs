{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE DefaultSignatures          #-}
{-# LANGUAGE DeriveDataTypeable         #-}
{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE EmptyDataDecls             #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE FlexibleInstances          #-}
{-# LANGUAGE GADTs                      #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses      #-}
{-# LANGUAGE QuasiQuotes                #-}
{-# LANGUAGE TemplateHaskell            #-}
{-# LANGUAGE TypeFamilies               #-}

module Snaplet.Authentication.Schema where

import           Data.Aeson.TH       (deriveJSON)
import           Data.Text           hiding (head)
import           Data.Time.Clock
import           Database.Persist.TH
import           GHC.Generics        (Generic)
import           Kashmir.Aeson
import           Kashmir.UUID
import           Prelude             hiding (id)

share [mkPersist sqlSettings,mkMigrate "migrateAccounts"]
      [persistLowerCase|
  Account
    accountId UUID sqltype=uuid
    created UTCTime
    Primary accountId
    deriving Read Show Eq Generic

  AccountUidpwd
    accountId UUID sqltype=uuid
    username Text sqltype=text
    password Text sqltype=text
    Primary username
    deriving Read Show Eq Generic
  |]

$(deriveJSON (dropPrefixJSONOptions "account")
             ''Account)
