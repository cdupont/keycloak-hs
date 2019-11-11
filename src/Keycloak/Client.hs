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
import           Data.Text as T hiding (head, tail, map)
import           Data.Maybe
import           Data.Either
import           Data.List as L
import           Data.Map hiding (map, lookup)
import           Data.String.Conversions
import qualified Data.ByteString.Lazy as BL
import           Keycloak.Types
import           Network.HTTP.Client as HC hiding (responseBody, path)
import           Network.HTTP.Types.Status
import           Network.HTTP.Types (renderQuery)
import           Network.Wreq as W hiding (statusCode)
import           Network.Wreq.Types
import           System.Log.Logger
import           Web.JWT as JWT
import           Safe

-- * Permissions

-- | Returns true if the resource is authorized under the given scope.
isAuthorized :: ResourceId -> ScopeName -> Token -> Keycloak Bool
isAuthorized res scope tok = do
  r <- try $ checkPermission res scope tok
  case r of
    Right _ -> return True
    Left e | (statusCode <$> getErrorStatus e) == Just 403 -> return False
    Left e -> throwError e --rethrow the error

-- | Return the permissions for the permission requests.
getPermissions :: [PermReq] -> Token -> Keycloak [Permission]
getPermissions reqs tok = do
  debug "Get all permissions"
  client <- asks _confClientId
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
      throwError $ ParseError $ pack (show err2)
  where
    getPermString :: PermReq -> [Text]
    getPermString (PermReq (Just (ResourceId rid)) []) = [rid]
    getPermString (PermReq (Just (ResourceId rid)) scopes) = map (\(ScopeName s) -> (rid <> "#" <> s)) scopes
    getPermString (PermReq Nothing scopes) = map (\(ScopeName s) -> ("#" <> s)) scopes

-- | Checks if a scope is permitted on a resource. An HTTP Exception 403 will be thrown if not.
checkPermission :: ResourceId -> ScopeName -> Token -> Keycloak ()
checkPermission (ResourceId res) (ScopeName scope) tok = do
  debug $ "Checking permissions: " ++ (show res) ++ " " ++ (show scope)
  client <- asks _confClientId
  let dat = ["grant_type" := ("urn:ietf:params:oauth:grant-type:uma-ticket" :: Text),
             "audience" := client,
             "permission"  := res <> "#" <> scope]
  void $ keycloakPost "protocol/openid-connect/token" dat tok


-- * Tokens

-- | Retrieve the user's token. This token will be used for every other Keycloak calls.
getUserAuthToken :: Username -> Password -> Keycloak Token
getUserAuthToken username password = do 
  debug "Get user token"
  client <- asks _confClientId
  secret <- asks _confClientSecret
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

-- | return a Client token. It is useful to create Resources.
getClientAuthToken :: Keycloak Token
getClientAuthToken = do
  debug "Get client token"
  client <- asks _confClientId
  secret <- asks _confClientSecret
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
      Just (String u) -> u
      _ -> error "preferred_username not present in token" 
    Nothing -> error "Error while decoding token"


-- * Resource

-- | Create an authorization resource in Keycloak, under the configured client.
createResource :: Resource -> Token -> Keycloak ResourceId
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
      throwError $ ParseError $ pack (show err2)

-- | Delete the resource
deleteResource :: ResourceId -> Token -> Keycloak ()
deleteResource (ResourceId rid) tok = do
  --tok2 <- getClientAuthToken 
  keycloakDelete ("authz/protection/resource_set/" <> rid) tok
  return ()

-- | Delete all resources in Keycloak
deleteAllResources :: Token -> Keycloak ()
deleteAllResources tok = do
  debug "Deleting all Keycloak resources..."
  ids <- getAllResourceIds
  res <- mapM (\rid -> try $ deleteResource rid tok) ids
  debug $ "Deleted " ++ (show $ L.length $ rights res) ++ " resources out of " ++ (show $ L.length ids)

-- | get a single resource
getResource :: ResourceId -> Token -> Keycloak Resource
getResource (ResourceId rid) tok = do
  body <- keycloakGet ("authz/protection/resource_set/" <> rid) tok
  case eitherDecode body of
    Right ret -> do
      return ret
    Left (err2 :: String) -> do
      debug $ "Keycloak parse error: " ++ (show err2) 
      throwError $ ParseError $ pack (show err2)

-- | get all resources IDs
getAllResourceIds :: Keycloak [ResourceId]
getAllResourceIds = do
  debug "Get all resources"
  tok2 <- getClientAuthToken 
  body <- keycloakGet ("authz/protection/resource_set?max=1000") tok2
  case eitherDecode body of
    Right ret -> do
      return ret
    Left (err2 :: String) -> do
      debug $ "Keycloak parse error: " ++ (show err2) 
      throwError $ ParseError $ pack (show err2)

-- | Update a resource
updateResource :: Resource -> Token -> Keycloak ResourceId
updateResource = createResource

-- * Users

-- | Get users. Default number of users is 100. Parameters max and first allow to paginate and retrieve more than 100 users.
getUsers :: Maybe Max -> Maybe First -> Maybe Username -> Token -> Keycloak [User]
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
      throwError $ ParseError $ pack (show err2)

-- | Get a single user, based on his Id
getUser :: UserId -> Token -> Keycloak User
getUser (UserId uid) tok = do
  body <- keycloakAdminGet ("users/" <> (convertString uid)) tok 
  debug $ "Keycloak success: " ++ (show body) 
  case eitherDecode body of
    Right ret -> do
      debug $ "Keycloak success: " ++ (show ret) 
      return ret
    Left (err2 :: String) -> do
      debug $ "Keycloak parse error: " ++ (show err2) 
      throwError $ ParseError $ pack (show err2)

-- | Create a user
createUser :: User -> Token -> Keycloak UserId
createUser user tok = do
  res <- keycloakAdminPost ("users/") (toJSON user) tok 
  debug $ "Keycloak success: " ++ (show res) 
  return $ UserId $ convertString res

-- | Get a single user, based on his Id
updateUser :: UserId -> User -> Token -> Keycloak ()
updateUser (UserId uid) user tok = do
  keycloakAdminPut ("users/" <> (convertString uid)) (toJSON user) tok 
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
    Left er -> do
      warn $ "Keycloak HTTP error: " ++ (show er)
      throwError $ HTTPError er

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
    Left er -> do
      warn $ "Keycloak HTTP error: " ++ (show er)
      throwError $ HTTPError er

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
keycloakGet :: Path -> Token -> Keycloak BL.ByteString
keycloakGet path tok = do 
  (KCConfig baseUrl realm _ _) <- ask
  let opts = W.defaults & W.header "Authorization" .~ ["Bearer " <> (unToken tok)]
  let url = (unpack $ baseUrl <> "/realms/" <> realm <> "/" <> path) 
  info $ "Issuing KEYCLOAK GET with url: " ++ (show url) 
  debug $ "  headers: " ++ (show $ opts ^. W.headers) 
  eRes <- C.try $ liftIO $ W.getWith opts url
  case eRes of 
    Right res -> do
      return $ fromJust $ res ^? responseBody
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

