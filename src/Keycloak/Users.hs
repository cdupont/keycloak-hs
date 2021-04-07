{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE ViewPatterns #-}

-- |
-- This module helps you manage users in Keycloak.
-- You can create, read and update users.
-- To activate this, you need to give the role "manage users" to your user in Keycloak.
-- For this, go in your user, select the "Role mappings" tab.
-- Then in "client Roles", select "realm management" and assign the role "manage-users".
-- 
-- Example usage:
-- 
-- @
-- -- Get a JWT from Keycloak. A JWT can then be used to authenticate yourself.
-- jwt <- getJWT "demo" "demo" 
-- 
-- users <- getUsers Nothing Nothing Nothing jwt
-- liftIO $ putStrLn $ "All Users: " ++ (show users)
-- @

module Keycloak.Users where

import           Control.Monad.IO.Class
import           Data.Aeson as JSON
import           Data.Text as T hiding (head, tail, map)
import           Data.String.Conversions
import           Keycloak.Types
import           Keycloak.Utils as U
import           Network.HTTP.Types (renderQuery)

-- * Users

-- | Get users. Default number of users is 100. Parameters max and first allow to paginate and retrieve more than 100 users.
getUsers :: MonadIO m => Maybe Max -> Maybe First -> Maybe Username -> JWT ->  KeycloakT m [User]
getUsers mmax first username tok = do
  let query = maybe [] (\m -> [("max", Just $ convertString $ show m)]) mmax
           ++ maybe [] (\f -> [("first", Just $ convertString $ show f)]) first
           ++ maybe [] (\u -> [("username", Just $ convertString u)]) username
  body <- keycloakAdminGet ("users" <> (convertString $ renderQuery True query)) tok 
  debug $ "Keycloak success" 
  case eitherDecode body of
    Right ret -> do
      debug $ "Keycloak success: " ++ (show ret) 
      return ret
    Left (err2 :: String) -> do
      debug $ "Keycloak parse error: " ++ (show err2) 
      kcError $ ParseError $ pack (show err2)

-- | Get a single user, based on his Id
getUser :: MonadIO m => UserId -> JWT ->  KeycloakT m User
getUser (UserId uid) tok = do
  body <- keycloakAdminGet ("users/" <> (convertString uid)) tok 
  debug $ "Keycloak success: " ++ (show body) 
  case eitherDecode body of
    Right ret -> do
      debug $ "Keycloak success: " ++ (show ret) 
      return ret
    Left (err2 :: String) -> do
      debug $ "Keycloak parse error: " ++ (show err2) 
      kcError $ ParseError $ pack (show err2)

-- | Create a user
createUser :: MonadIO m => User -> JWT ->  KeycloakT m UserId
createUser user tok = do
  res <- keycloakAdminPost ("users/") (toJSON user) tok 
  debug $ "Keycloak success: " ++ (show res) 
  return $ UserId $ convertString res

-- | Get a single user, based on his Id
updateUser :: MonadIO m => UserId -> User -> JWT ->  KeycloakT m ()
updateUser (UserId uid) user tok = do
  keycloakAdminPut ("users/" <> (convertString uid)) (toJSON user) tok 
  return ()


