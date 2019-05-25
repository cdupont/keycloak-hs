{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE ViewPatterns #-}

module Keycloak.Client where

import           Control.Lens hiding ((.=))
import           Control.Monad.Reader as R
import qualified Control.Monad.Catch as C
import           Control.Monad.Except (throwError, catchError, MonadError)
import           Data.Aeson as JSON
import           Data.Aeson.Types hiding ((.=))
import           Data.Text as T hiding (head, tail, map, lookup)
import           Data.Text.Encoding
import           Data.Maybe
import           Data.List as L
import           Data.Map hiding (map, lookup)
import           Data.String.Conversions
import           Data.Monoid hiding (First)
import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Lazy as BL
import           Keycloak.Types
import           Network.HTTP.Client as HC hiding (responseBody)
import           Network.HTTP.Types.Status
import           Network.HTTP.Types.Method 
import           Network.HTTP.Types (renderQuery)
import           Network.Wreq as W hiding (statusCode)
import           Network.Wreq.Types
import           System.Log.Logger
import           Debug.Trace
import           System.IO.Unsafe
import           Web.JWT as JWT

-- * Permissions

-- | Checks if a scope is permitted on a resource. An HTTP Exception 403 will be thrown if not.
checkPermission :: ResourceId -> ScopeName -> Token -> Keycloak ()
checkPermission (ResourceId res) scope tok = do
  debug $ "Checking permissions: " ++ (show res) ++ " " ++ (show scope)
  client <- asks _clientId
  let dat = ["grant_type" := ("urn:ietf:params:oauth:grant-type:uma-ticket" :: Text),
             "audience" := client,
             "permission"  := res <> "#" <> scope]
  keycloakPost "protocol/openid-connect/token" dat tok
  return ()

-- | Returns true id the resource is authorized under the given scope.
isAuthorized :: ResourceId -> ScopeName -> Token -> Keycloak Bool
isAuthorized res scope tok = do
  r <- try $ checkPermission res scope tok
  case r of
    Right _ -> return True
    Left e | (statusCode <$> getErrorStatus e) == Just 403 -> return False
    Left e -> throwError e --rethrow the error

-- | Return the permissions for all resources, under the given scopes.
getAllPermissions :: [ScopeName] -> Token -> Keycloak [Permission]
getAllPermissions scopes tok = do
  debug "Get all permissions"
  client <- asks _clientId
  let dat = ["grant_type" := ("urn:ietf:params:oauth:grant-type:uma-ticket" :: Text),
             "audience" := client,
             "response_mode" := ("permissions" :: Text)]
             <> map (\s -> "permission" := ("#" <> s)) scopes
  body <- keycloakPost "protocol/openid-connect/token" dat tok
  case eitherDecode body of
    Right ret -> do
      return ret
    Left (err2 :: String) -> do
      debug $ "Keycloak parse error: " ++ (show err2) 
      throwError $ ParseError $ pack (show err2)


-- * Tokens

-- | Retrieve the user's token
getUserAuthToken :: Username -> Password -> Keycloak Token
getUserAuthToken username password = do 
  debug "Get user token"
  client <- asks _clientId
  secret <- asks _clientSecret
  let dat = ["client_id" := client, 
             "client_secret" := secret,
             "grant_type" := ("password" :: Text),
             "password" := password,
             "username" := username]
  body <- keycloakPost' "protocol/openid-connect/token" dat
  debug $ "Keycloak: " ++ (show body) 
  case eitherDecode body of
    Right ret -> do 
      debug $ "Keycloak success: " ++ (show ret) 
      return $ Token $ convertString $ accessToken ret
    Left err2 -> do
      debug $ "Keycloak parse error: " ++ (show err2) 
      throwError $ ParseError $ pack (show err2)

-- | return a Client token
getClientAuthToken :: Keycloak Token
getClientAuthToken = do
  debug "Get client token"
  client <- asks _clientId
  secret <- asks _clientSecret
  let dat = ["client_id" := client, 
             "client_secret" := secret,
             "grant_type" := ("client_credentials" :: Text)]
  body <- keycloakPost' "protocol/openid-connect/token" dat
  case eitherDecode body of
    Right ret -> do
      debug $ "Keycloak success: " ++ (show ret) 
      return $ Token $ convertString $ accessToken ret
    Left err2 -> do
      debug $ "Keycloak parse error: " ++ (show err2) 
      throwError $ ParseError $ pack (show err2)


-- | Extract user name from a token
getUsername :: Token -> Username
getUsername (Token tok) = do 
  case JWT.decode $ convertString tok of
    Just t -> case (unClaimsMap $ unregisteredClaims $ claims t) !? "preferred_username" of
      Just (String un) -> un
      _ -> error "preferred_username not present in token" 
    Nothing -> error "Error while decoding token"


-- * Resource

-- | Create a resource.
createResource :: Resource -> Token -> Keycloak ResourceId
createResource r tok = do
  debug $ convertString $ "Creating resource: " <> (JSON.encode r)
  -- The user token might not be suitable because it can use another client (such as "dashboard"). 
  -- however we need "api-server" as client because it's the resource authorization server.
  tok2 <- getClientAuthToken 
  body <- keycloakPost "authz/protection/resource_set" (toJSON r) tok2
  debug $ convertString $ "Created resource: " ++ convertString body
  case eitherDecode body of
    Right ret -> do
      debug $ "Keycloak success: " ++ (show ret) 
      return $ fromJust $ resId ret
    Left err2 -> do
      debug $ "Keycloak parse error: " ++ (show err2) 
      throwError $ ParseError $ pack (show err2)

-- | Delete the resource
deleteResource :: ResourceId -> Token -> Keycloak ()
deleteResource (ResourceId rid) tok = do
  tok2 <- getClientAuthToken 
  keycloakDelete ("authz/protection/resource_set/" <> rid) tok2 
  return ()


-- * Users

-- | Get users. Default number of users is 100. Parameters max and first allow to paginate and retrieve more than 100 users.
getUsers :: Maybe Max -> Maybe First -> Maybe Username -> Token -> Keycloak [User]
getUsers max first username tok = do
  let query = maybe [] (\l -> [("limit", Just $ convertString $ show l)]) max
           ++ maybe [] (\m -> [("max", Just $ convertString $ show m)]) first
           ++ maybe [] (\u -> [("username", Just $ convertString u)]) username
  body <- keycloakAdminGet ("users" <> (convertString $ renderQuery True query)) tok 
  debug $ "Keycloak success: " ++ (show body) 
  case eitherDecode body of
    Right ret -> do
      debug $ "Keycloak success: " ++ (show ret) 
      return ret
    Left (err2 :: String) -> do
      debug $ "Keycloak parse error: " ++ (show err2) 
      throwError $ ParseError $ pack (show err2)

-- | Get a single user, based on his Id
getUser :: UserId -> Token -> Keycloak User
getUser (UserId id) tok = do
  body <- keycloakAdminGet ("users/" <> (convertString id)) tok 
  debug $ "Keycloak success: " ++ (show body) 
  case eitherDecode body of
    Right ret -> do
      debug $ "Keycloak success: " ++ (show ret) 
      return ret
    Left (err2 :: String) -> do
      debug $ "Keycloak parse error: " ++ (show err2) 
      throwError $ ParseError $ pack (show err2)

-- | Get a single user, based on his Id
postUser :: User -> Token -> Keycloak UserId
postUser user tok = do
  res <- keycloakAdminPost ("users/") (toJSON user) tok 
  debug $ "Keycloak success: " ++ (show res) 
  return $ UserId $ convertString res

-- | Get a single user, based on his Id
putUser :: UserId -> User -> Token -> Keycloak ()
putUser (UserId id) user tok = do
  keycloakAdminPut ("users/" <> (convertString id)) (toJSON user) tok 
  return ()


-- * Keycloak basic requests

-- | Perform post to Keycloak.
keycloakPost :: (Postable dat, Show dat) => Path -> dat -> Token -> Keycloak BL.ByteString
keycloakPost path dat tok = do 
  (KCConfig baseUrl realm _ _) <- ask
  let opts = W.defaults & W.header "Authorization" .~ ["Bearer " <> (unToken tok)]
  let url = (unpack $ baseUrl <> "/realms/" <> realm <> "/" <> path) 
  info $ "Issuing KEYCLOAK POST with url: " ++ (show url) 
  debug $ "  data: " ++ (show dat) 
  --debug $ "  headers: " ++ (show $ opts ^. W.headers) 
  eRes <- C.try $ liftIO $ W.postWith opts url dat
  case eRes of 
    Right res -> do
      return $ fromJust $ res ^? responseBody
    Left err -> do
      warn $ "Keycloak HTTP error: " ++ (show err)
      throwError $ HTTPError err

-- | Perform post to Keycloak, without token.
keycloakPost' :: (Postable dat, Show dat) => Path -> dat -> Keycloak BL.ByteString
keycloakPost' path dat = do 
  (KCConfig baseUrl realm _ _) <- ask
  let opts = W.defaults
  let url = (unpack $ baseUrl <> "/realms/" <> realm <> "/" <> path) 
  info $ "Issuing KEYCLOAK POST with url: " ++ (show url) 
  debug $ "  data: " ++ (show dat) 
  --debug $ "  headers: " ++ (show $ opts ^. W.headers) 
  eRes <- C.try $ liftIO $ W.postWith opts url dat
  case eRes of 
    Right res -> do
      return $ fromJust $ res ^? responseBody
    Left err -> do
      warn $ "Keycloak HTTP error: " ++ (show err)
      throwError $ HTTPError err

-- | Perform delete to Keycloak.
keycloakDelete :: Path -> Token -> Keycloak ()
keycloakDelete path tok = do 
  (KCConfig baseUrl realm _ _) <- ask
  let opts = W.defaults & W.header "Authorization" .~ ["Bearer " <> (unToken tok)]
  let url = (unpack $ baseUrl <> "/realms/" <> realm <> "/" <> path) 
  info $ "Issuing KEYCLOAK DELETE with url: " ++ (show url) 
  debug $ "  headers: " ++ (show $ opts ^. W.headers) 
  eRes <- C.try $ liftIO $ W.deleteWith opts url
  case eRes of 
    Right res -> return ()
    Left err -> do
      warn $ "Keycloak HTTP error: " ++ (show err)
      throwError $ HTTPError err

-- | Perform get to Keycloak on admin API
keycloakAdminGet :: Path -> Token -> Keycloak BL.ByteString
keycloakAdminGet path tok = do 
  (KCConfig baseUrl realm _ _) <- ask
  let opts = W.defaults & W.header "Authorization" .~ ["Bearer " <> (unToken tok)]
  let url = (unpack $ baseUrl <> "/admin/realms/" <> realm <> "/" <> path) 
  info $ "Issuing KEYCLOAK GET with url: " ++ (show url) 
  debug $ "  headers: " ++ (show $ opts ^. W.headers) 
  eRes <- C.try $ liftIO $ W.getWith opts url
  case eRes of 
    Right res -> do
      return $ fromJust $ res ^? responseBody
    Left err -> do
      warn $ "Keycloak HTTP error: " ++ (show err)
      throwError $ HTTPError err

-- | Perform post to Keycloak.
keycloakAdminPost :: (Postable dat, Show dat) => Path -> dat -> Token -> Keycloak BL.ByteString
keycloakAdminPost path dat tok = do 
  (KCConfig baseUrl realm _ _) <- ask
  let opts = W.defaults & W.header "Authorization" .~ ["Bearer " <> (unToken tok)]
  let url = (unpack $ baseUrl <> "/admin/realms/" <> realm <> "/" <> path) 
  info $ "Issuing KEYCLOAK POST with url: " ++ (show url) 
  debug $ "  data: " ++ (show dat) 
  --debug $ "  headers: " ++ (show $ opts ^. W.headers) 
  eRes <- C.try $ liftIO $ W.postWith opts url dat
  case eRes of 
    Right res -> do
      debug $ (show eRes)
      let headers = fromJust $ res ^? W.responseHeaders
      return $ convertString $ L.last $ T.split (== '/') $ convertString $ fromJust $ lookup "Location" headers
    Left err -> do
      warn $ "Keycloak HTTP error: " ++ (show err)
      throwError $ HTTPError err

-- | Perform put to Keycloak.
keycloakAdminPut :: (Putable dat, Show dat) => Path -> dat -> Token -> Keycloak ()
keycloakAdminPut path dat tok = do 
  (KCConfig baseUrl realm _ _) <- ask
  let opts = W.defaults & W.header "Authorization" .~ ["Bearer " <> (unToken tok)]
  let url = (unpack $ baseUrl <> "/admin/realms/" <> realm <> "/" <> path) 
  info $ "Issuing KEYCLOAK PUT with url: " ++ (show url) 
  debug $ "  data: " ++ (show dat) 
  debug $ "  headers: " ++ (show $ opts ^. W.headers) 
  eRes <- C.try $ liftIO $ W.putWith opts url dat
  case eRes of 
    Right res -> return ()
    Left err -> do
      warn $ "Keycloak HTTP error: " ++ (show err)
      throwError $ HTTPError err
-- * Helpers

debug, warn, info, err :: (MonadIO m) => String -> m ()
debug s = liftIO $ debugM "Keycloak" s
info s  = liftIO $ infoM "Keycloak" s
warn s  = liftIO $ warningM "Keycloak" s
err s   = liftIO $ errorM "Keycloak" s

getErrorStatus :: KCError -> Maybe Status 
getErrorStatus (HTTPError (HttpExceptionRequest _ (StatusCodeException r _))) = Just $ HC.responseStatus r
getErrorStatus _ = Nothing

try :: MonadError a m => m b -> m (Either a b)
try act = catchError (Right <$> act) (return . Left)

