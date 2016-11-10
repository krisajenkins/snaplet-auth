module Snaplet.Authentication.Queries
  ( lookupByEmail
  , hashFor
  , resetUidpwdUserPassword
  , createUidpwdUser
  , getGithubAccessToken
  , handleSql
  , HashedPassword
  ) where

import           Control.Exception                (throw)
import           Control.Monad.IO.Class
import           Crypto.BCrypt
import           Data.Text                        (Text)
import           Data.Text.Encoding
import           Data.Time
import           Database.Esqueleto
import           Kashmir.Email
import           Kashmir.Github.Types
import           Kashmir.UUID
import           Snap
import           Snaplet.Authentication.Common
import           Snaplet.Authentication.Exception
import           Snaplet.Authentication.Schema

lookupByEmail :: Email -> SqlPersistM (Maybe (Account, AccountUidpwd))
lookupByEmail email =
    onlyOne . fmap unwrap <$>
    (select . from $
     \(account `InnerJoin` accountUidpwd) -> do
         on $ account ^. AccountAccountId ==. accountUidpwd ^. AccountUidpwdAccountId
         where_ (accountUidpwd ^. AccountUidpwdEmail ==. val email)
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
                 -> Email
                 -> HashedPassword
                 -> SqlPersistM (Key Account)
createUidpwdUser uuid created email hashedPassword = do
    accountKey <- insert $ Account uuid created
    _ <-
        insert
            AccountUidpwd
            { accountUidpwdAccountId = unAccountKey accountKey
            , accountUidpwdEmail = email
            , accountUidpwdPassword = hash hashedPassword
            }
    return accountKey

resetUidpwdUserPassword :: UUID -> HashedPassword -> SqlPersistM (Maybe Account)
resetUidpwdUserPassword userId hashedPassword = do
    updatedRows <-
        updateCount $
        \accountUidpwd -> do
            set
                accountUidpwd
                [AccountUidpwdPassword =. val (hash hashedPassword)]
            where_ ((accountUidpwd ^. AccountUidpwdAccountId) ==. val userId)
    case updatedRows of
        0 -> return Nothing
        1 -> get (AccountKey userId)

getGithubAccessToken :: Key Account -> SqlPersistM (Maybe AccessToken)
getGithubAccessToken key =
    onlyOne . fmap unValue <$>
    (select . from $
     \accountGithub -> do
         where_ (accountGithub ^. AccountGithubAccountId ==. val key)
         return (accountGithub ^. AccountGithubAccessToken))

------------------------------------------------------------

handleSql :: SqlPersistM a -> Handler b (Authentication b) a
handleSql sql = do
    connection <- getConnection
    liftIO $ runSqlPersistMPool sql connection
