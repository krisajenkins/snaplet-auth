{-# LANGUAGE OverloadedStrings #-}
module Snaplet.Authentication.Utils (unauthorized) where

import           Snap

handleError :: MonadSnap m => Int -> m b
handleError errorCode =
  do modifyResponse $ setResponseCode errorCode
     writeText ""
     getResponse >>= finishWith

unauthorized :: (MonadSnap m) => m b
unauthorized = handleError 401
