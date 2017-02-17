module Snaplet.Authentication.Exception
  ( AuthenticationException(..)
  ) where

import Control.Exception

data AuthenticationException
  = DuplicateAccount
  | AccountNotFound
  | Unauthenticated
  deriving (Show)

instance Exception AuthenticationException
