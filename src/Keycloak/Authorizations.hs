{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- |
-- This module helps you manage resources authorization with Keycloak.
-- 
-- In Keycloak, in the client, activate "Authorization Enabled" and set "Valid Redirect URIs" as "*".
-- You then need to create your scopes, policies and permissions in the authorization tab.
-- If you are unsure, set the "Policy Enforcement Mode" as permissive, so that a positive permission will be given with resources without policy.
-- 
-- The example below shows how to retrieve a token from Keycloak, and then retrieve the permissions of a user on a specific resource.
-- 
-- @
-- -- Let's get a token for a specific user login/password
-- userToken <- getJWT "demo" "demo"
-- 
-- -- Can I access this resource?
-- isAuth <- isAuthorized resId (ScopeName "view") userToken
-- 
-- liftIO $ putStrLn $ "User 'demo' can access resource 'demo': " ++ (show isAuth)
-- 
-- -- We can also retrieve all the permissions for our user.
-- perms <- getPermissions [PermReq Nothing [ScopeName "view"]] userToken
-- 
-- liftIO $ putStrLn $ "All permissions: " ++ (show perms)
-- @

module Keycloak.Authorizations where

import           Control.Monad.Reader as R
import           Data.Aeson as JSON
import           Data.Text as T hiding (head, tail, map)
import           Data.Either
import           Data.List as L
import           Data.String.Conversions
import           Keycloak.Types
import           Keycloak.Tokens
import           Keycloak.Utils as U
import           Control.Lens
import           Network.HTTP.Types.Status
import           Network.Wreq as W hiding (statusCode)
import           Safe

-- * Permissions

-- | Returns true if the resource is authorized under the given scope.
isAuthorized :: MonadIO m => ResourceId -> ScopeName -> JWT -> KeycloakT m Bool
isAuthorized res scope tok = do
  r <- U.try $ checkPermission res scope tok
  case r of
    Right _ -> return True
    Left e | (statusCode <$> U.getErrorStatus e) == Just 403 -> return False
    Left e -> kcError e --rethrow the error

-- | Return the permissions for the permission requests.
getPermissions :: MonadIO m => [PermReq] -> JWT -> KeycloakT m [Permission]
getPermissions reqs tok = do
  debug "Get all permissions"
  client <- viewConfig $ confAdapterConfig.confResource
  let dat = ["grant_type" := ("urn:ietf:params:oauth:grant-type:uma-ticket" :: Text),
             "audience" := client,
             "response_mode" := ("permissions" :: Text)] 
             <> map (\p -> "permission" := p) (join $ map getPermString reqs)
  body <- keycloakPost "protocol/openid-connect/token" dat tok
  case eitherDecode body of
    Right ret -> do
      debug $ "Keycloak returned perms: " ++ (show ret)
      return ret
    Left (err2 :: String) -> do
      debug $ "Keycloak parse error: " ++ (show err2) 
      kcError $ ParseError $ pack (show err2)
  where
    getPermString :: PermReq -> [Text]
    getPermString (PermReq (Just (ResourceId rid)) []) = [rid]
    getPermString (PermReq (Just (ResourceId rid)) scopes) = map (\(ScopeName s) -> (rid <> "#" <> s)) scopes
    getPermString (PermReq Nothing scopes) = map (\(ScopeName s) -> ("#" <> s)) scopes

-- | Checks if a scope is permitted on a resource. An HTTP Exception 403 will be thrown if not.
checkPermission :: MonadIO m => ResourceId -> ScopeName -> JWT -> KeycloakT m ()
checkPermission (ResourceId res) (ScopeName scope) tok = do
  debug $ "Checking permissions: " ++ (show res) ++ " " ++ (show scope)
  client <- viewConfig $ confAdapterConfig.confResource
  let dat = ["grant_type" := ("urn:ietf:params:oauth:grant-type:uma-ticket" :: Text),
             "audience" := client,
             "permission"  := res <> "#" <> scope]
  void $ keycloakPost "protocol/openid-connect/token" dat tok


-- * Resource

-- | Create an authorization resource in Keycloak, under the configured client.
createResource :: MonadIO m => Resource -> JWT -> KeycloakT m ResourceId
createResource r tok = do
  debug $ convertString $ "Creating resource: " <> (JSON.encode r)
  body <- keycloakPost "authz/protection/resource_set" (toJSON r) tok
  debug $ convertString $ "Created resource: " ++ convertString body
  case eitherDecode body of
    Right ret -> do
      debug $ "Keycloak success: " ++ (show ret)
      return $ fromJustNote "create" $ resId ret
    Left err2 -> do
      debug $ "Keycloak parse error: " ++ (show err2) 
      kcError $ ParseError $ pack (show err2)

-- | Delete the resource
deleteResource :: MonadIO m => ResourceId -> JWT -> KeycloakT m ()
deleteResource (ResourceId rid) tok = do
  --tok2 <- getClientAuthToken 
  keycloakDelete ("authz/protection/resource_set/" <> rid) tok
  return ()

-- | Delete all resources in Keycloak
deleteAllResources :: MonadIO m => JWT ->  KeycloakT m ()
deleteAllResources tok = do
  debug "Deleting all Keycloak resources..."
  ids <- getAllResourceIds
  res <- mapM (\rid -> try $ deleteResource rid tok) ids
  debug $ "Deleted " ++ (show $ L.length $ rights res) ++ " resources out of " ++ (show $ L.length ids)

-- | get a single resource
getResource :: MonadIO m => ResourceId -> JWT -> KeycloakT m Resource
getResource (ResourceId rid) tok = do
  body <- keycloakGet ("authz/protection/resource_set/" <> rid) tok
  case eitherDecode body of
    Right ret -> do
      return ret
    Left (err2 :: String) -> do
      debug $ "Keycloak parse error: " ++ (show err2) 
      kcError $ ParseError $ pack (show err2)

-- | get all resources IDs
getAllResourceIds :: MonadIO m => KeycloakT m [ResourceId]
getAllResourceIds = do
  debug "Get all resources"
  tok2 <- getClientJWT 
  body <- keycloakGet ("authz/protection/resource_set?max=1000") tok2
  case eitherDecode body of
    Right ret -> do
      return ret
    Left (err2 :: String) -> do
      debug $ "Keycloak parse error: " ++ (show err2) 
      kcError $ ParseError $ pack (show err2)

-- | Update a resource
updateResource :: MonadIO m => Resource -> JWT ->  KeycloakT m ResourceId
updateResource = createResource
