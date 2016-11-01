module Snaplet.Authentication.Queries
  ( lookupByUsername
  , hashFor
  , createUidpwdUser
  , getGithubAccessToken
  ) where

import           Control.Exception
import           Crypto.BCrypt
import           Data.Text                        (Text)
import           Data.Text.Encoding
import           Data.Time
import           Database.Esqueleto
import           Kashmir.Github.Types
import           Kashmir.UUID
import           Snaplet.Authentication.Exception
import           Snaplet.Authentication.Schema

lookupByUsername :: Text -> SqlPersistM (Maybe (Account, AccountUidpwd))
lookupByUsername username =
    onlyOne . fmap unwrap <$>
    (select . from $
     \(account `InnerJoin` accountUidpwd) -> do
         on $ account ^. AccountAccountId ==. accountUidpwd ^. AccountUidpwdAccountId
         where_ (accountUidpwd ^. AccountUidpwdUsername ==. val username)
         return (account, accountUidpwd))

unwrap :: (Entity a, Entity b) -> (a, b)
unwrap (e, f) = (entityVal e, entityVal f)

onlyOne :: [a] -> Maybe a
onlyOne xs =
    case xs of
        [] -> Nothing
        [x] -> Just x
        _ -> throw DuplicateAccount

data HashedPassword = HashedPassword
    { hash :: Text
    }

hashFor :: Text -> IO (Maybe HashedPassword)
hashFor password = do
    hashed <- hashPasswordUsingPolicy fastBcryptHashingPolicy $ encodeUtf8 password
    return (HashedPassword . decodeUtf8 <$> hashed)

createUidpwdUser :: UUID
                 -> UTCTime
                 -> Text
                 -> HashedPassword
                 -> SqlPersistM (Key Account)
createUidpwdUser uuid created username hashedPassword = do
    accountKey <- insert $ Account uuid created
    _ <-
        insert
            AccountUidpwd
            { accountUidpwdAccountId = unAccountKey accountKey
            , accountUidpwdUsername = username
            , accountUidpwdPassword = hash hashedPassword
            }
    return accountKey

getGithubAccessToken :: Key Account -> SqlPersistM (Maybe AccessToken)
getGithubAccessToken key =
    onlyOne . fmap unValue <$>
    (select . from $
     \accountGithub -> do
         where_ (accountGithub ^. AccountGithubAccountId ==. val key)
         return (accountGithub ^. AccountGithubAccessToken))
