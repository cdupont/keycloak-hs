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
import           Data.Aeson.BetterErrors as AB
import           Data.Text hiding (head, tail, map)
import           Data.Text.Encoding
import           Data.Maybe
import           Data.ByteString.Base64 as B64
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


-------------------
-- * Permissions --
-------------------

checkPermission :: ResourceId -> ScopeName -> Maybe Token -> Keycloak ()
checkPermission (ResourceId res) scope tok = do
  debug $ "Checking permissions: " ++ (show res) ++ " " ++ (show scope)
  client <- asks _clientId
  let dat = ["grant_type" := ("urn:ietf:params:oauth:grant-type:uma-ticket" :: Text),
             "audience" := client,
             "permission"  := res <> "#" <> scope]
  keycloakPostDef "protocol/openid-connect/token" dat tok
  return ()

isAuthorized :: ResourceId -> ScopeName -> Maybe Token -> Keycloak Bool
isAuthorized res scope tok = do
  r <- try $ checkPermission res scope tok
  case r of
    Right _ -> return True
    Left e | (statusCode <$> getErrorStatus e) == Just 403 -> return False
    Left e -> throwError e --rethrow the error

getAllPermissions :: [ScopeName] -> Maybe Token -> Keycloak [Permission]
getAllPermissions scopes mtok = do
  debug "Get all permissions"
  client <- asks _clientId
  let dat = ["grant_type" := ("urn:ietf:params:oauth:grant-type:uma-ticket" :: Text),
             "audience" := client,
             "response_mode" := ("permissions" :: Text)]
             <> map (\s -> "permission" := ("#" <> s)) scopes
  body <- keycloakPostDef "protocol/openid-connect/token" dat mtok
  case eitherDecode body of
    Right ret -> do
      debug $ "Keycloak success: " ++ (show ret) 
      return ret
    Left (err2 :: String) -> do
      debug $ "Keycloak parse error: " ++ (show err2) 
      throwError $ ParseError $ pack (show err2)


--------------
-- * Tokens --
--------------
  
getUserAuthToken :: Text -> Text -> Keycloak Token
getUserAuthToken username password = do 
  debug "Get user token"
  client <- asks _clientId
  secret <- asks _clientSecret
  let dat = ["client_id" := client, 
             "client_secret" := secret,
             "grant_type" := ("password" :: Text),
             "password" := password,
             "username" := username]
  body <- keycloakPost "protocol/openid-connect/token" dat Nothing 
  debug $ "Keycloak: " ++ (show body) 
  case eitherDecode body of
    Right ret -> do 
      debug $ "Keycloak success: " ++ (show ret) 
      return ret
    Left err2 -> do
      debug $ "Keycloak parse error: " ++ (show err2) 
      throwError $ ParseError $ pack (show err2)

getClientAuthToken :: Keycloak Token
getClientAuthToken = do
  debug "Get client token"
  client <- asks _clientId
  secret <- asks _clientSecret
  let dat = ["client_id" := client, 
             "client_secret" := secret,
             "grant_type" := ("client_credentials" :: Text)]
  body <- keycloakPost "protocol/openid-connect/token" dat Nothing
  case eitherDecode body of
    Right ret -> do
      debug $ "Keycloak success: " ++ (show ret) 
      return $ ret
    Left err2 -> do
      debug $ "Keycloak parse error: " ++ (show err2) 
      throwError $ ParseError $ pack (show err2)

decodeToken :: Token -> Either String TokenDec
decodeToken (Token tok) = case (BS.split '.' tok) ^? element 1 of
    Nothing -> Left "Token is not formed correctly"
    Just part2 -> case AB.parse parseTokenDec (traceShowId $ convertString $ B64.decodeLenient $ traceShowId part2) of
      Right td -> Right td
      Left (e :: ParseError String) -> Left $ show e

getUsername :: Token -> Maybe Username
getUsername tok = do 
  case decodeToken tok of
    Right t -> Just $ preferredUsername t
    Left e -> do
      traceM $ "Error while decoding token: " ++ (show e)
      Nothing

----------------
-- * Resource --
----------------

createResource :: Resource -> Maybe Token -> Keycloak ResourceId
createResource r mtok = do
  debug $ convertString $ "Creating resource: " <> (JSON.encode r)
  body <- keycloakPostDef "authz/protection/resource_set" (toJSON r) mtok
  debug $ convertString $ "Created resource: " ++ convertString body
  case eitherDecode body of
    Right ret -> do
      debug $ "Keycloak success: " ++ (show ret) 
      return $ fromJust $ resId ret
    Left err2 -> do
      debug $ "Keycloak parse error: " ++ (show err2) 
      throwError $ ParseError $ pack (show err2)

deleteResource :: ResourceId -> Maybe Token -> Keycloak ()
deleteResource (ResourceId rid) mtok = do
  keycloakDeleteDef ("authz/protection/resource_set/" <> rid) mtok 
  return ()


-------------
-- * Users --
-------------

getUsers :: Maybe Max -> Maybe First -> Keycloak [User]
getUsers max first = do
  tok <- getUserAuthToken "admin" "admin"
  let query = maybe [] (\l -> [("limit", Just $ convertString $ show l)]) max
           ++ maybe [] (\m -> [("max", Just $ convertString $ show m)]) first
  body <- keycloakAdminGet ("users" <> (convertString $ renderQuery True query)) (Just tok) 
  debug $ "Keycloak success: " ++ (show body) 
  case eitherDecode body of
    Right ret -> do
      debug $ "Keycloak success: " ++ (show ret) 
      return ret
    Left (err2 :: String) -> do
      debug $ "Keycloak parse error: " ++ (show err2) 
      throwError $ ParseError $ pack (show err2)

getUser :: UserId -> Keycloak User
getUser (UserId id) = do
  tok <- getUserAuthToken "admin" "admin"
  body <- keycloakAdminGet ("users/" <> (convertString id)) (Just tok) 
  debug $ "Keycloak success: " ++ (show body) 
  case eitherDecode body of
    Right ret -> do
      debug $ "Keycloak success: " ++ (show ret) 
      return ret
    Left (err2 :: String) -> do
      debug $ "Keycloak parse error: " ++ (show err2) 
      throwError $ ParseError $ pack (show err2)


-------------------------
-- * Keycloak requests --
-------------------------

-- Perform post to Keycloak with token.
-- If there is no token, retrieve a guest token
keycloakPostDef :: (Postable dat, Show dat) => Path -> dat -> Maybe Token -> Keycloak BL.ByteString
keycloakPostDef path dat mtok = do
  (KCConfig baseUrl realm _ _ _ _ guestId guestPass) <- ask
  tok <- case mtok of
       Just tok -> return tok
       Nothing -> getUserAuthToken guestId guestPass
  keycloakPost path dat (Just tok)

-- Perform post to Keycloak.
keycloakPost :: (Postable dat, Show dat) => Path -> dat -> Maybe Token -> Keycloak BL.ByteString
keycloakPost path dat mtok = do 
  (KCConfig baseUrl realm _ _ _ _ _ _) <- ask
  let opts = case mtok of
       Just tok -> W.defaults & W.header "Authorization" .~ ["Bearer " <> (unToken tok)]
       Nothing -> W.defaults
  let url = (unpack $ baseUrl <> "/realms/" <> realm <> "/" <> path) 
  info $ "Issuing KEYCLOAK POST with url: " ++ (show url) 
  debug $ "  data: " ++ (show dat) 
  debug $ "  headers: " ++ (show $ opts ^. W.headers) 
  eRes <- C.try $ liftIO $ W.postWith opts url dat
  case eRes of 
    Right res -> do
      return $ fromJust $ res ^? responseBody
    Left err -> do
      warn $ "Keycloak HTTP error: " ++ (show err)
      throwError $ HTTPError err

-- Perform delete to Keycloak with default user.
keycloakDeleteDef :: Path -> Maybe Token -> Keycloak ()
keycloakDeleteDef path mtok = do
  (KCConfig baseUrl realm _ _ _ _ guestId guestPass) <- ask
  tok <- case mtok of
       Just tok -> return tok
       Nothing -> getUserAuthToken guestId guestPass
  keycloakDelete path tok

-- Perform delete to Keycloak.
keycloakDelete :: Path -> Token -> Keycloak ()
keycloakDelete path tok = do 
  (KCConfig baseUrl realm _ _ _ _ _ _) <- ask
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

-- Perform get to Keycloak.
keycloakAdminGet :: Path -> Maybe Token -> Keycloak BL.ByteString
keycloakAdminGet path mtok = do 
  (KCConfig baseUrl realm _ _ _ _ _ _) <- ask
  let opts = case mtok of
       Just tok -> W.defaults & W.header "Authorization" .~ ["Bearer " <> (unToken tok)]
       Nothing -> W.defaults
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


---------------
-- * Helpers --
---------------

debug, warn, info, err :: (MonadIO m) => String -> m ()
debug s = liftIO $ debugM "API" s
info s  = liftIO $ infoM "API" s
warn s  = liftIO $ warningM "API" s
err s   = liftIO $ errorM "API" s

getErrorStatus :: KCError -> Maybe Status 
getErrorStatus (HTTPError (HttpExceptionRequest _ (StatusCodeException r _))) = Just $ HC.responseStatus r
getErrorStatus _ = Nothing

try :: MonadError a m => m b -> m (Either a b)
try act = catchError (Right <$> act) (return . Left)

