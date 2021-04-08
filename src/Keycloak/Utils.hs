{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE ViewPatterns #-}

module Keycloak.Utils where

import           Control.Lens hiding ((.=))
import           Control.Monad.Reader as R
import qualified Control.Monad.Catch as C
import           Control.Monad.Except (throwError, catchError, MonadError)
import           Data.Text as T hiding (head, tail, map)
import           Data.Maybe
import           Data.List as L
import           Data.String.Conversions
import qualified Data.ByteString.Lazy as BL
import           Keycloak.Types
import           Network.HTTP.Client as HC hiding (responseBody, path)
import           Network.HTTP.Types.Status
import           Network.Wreq as W hiding (statusCode)
import           Network.Wreq.Types
import           System.Log.Logger
import           Crypto.JWT as JWT


-- | Perform post to Keycloak.
keycloakPost :: (Postable dat, Show dat, MonadIO m) => Path -> dat -> JWT -> KeycloakT m BL.ByteString
keycloakPost path dat jwt = do
  (realm,baseUrl) <- viewRealmAndUrl
  let opts = W.defaults & W.header "Authorization" .~ ["Bearer " <> (convertString $ encodeCompact jwt)]
  let url = (unpack $ baseUrl <> "/realms/" <> realm <> "/" <> path) 
  info $ "Issuing KEYCLOAK POST with url: " ++ (show url) 
  debug $ "  data: " ++ (show dat) 
  --debug $ "  headers: " ++ (show $ opts ^. W.headers) 
  eRes <- liftIO $ C.try $ W.postWith opts url dat
  case eRes of 
    Right res -> do
      return $ fromJust $ res ^? responseBody
    Left er -> do
      warn $ "Keycloak HTTP error: " ++ (show er)
      kcError $ HTTPError er

-- | Perform post to Keycloak, without token.
keycloakPost' :: (Postable dat, Show dat, MonadIO m) => Path -> dat -> KeycloakT m BL.ByteString
keycloakPost' path dat = do 
  (realm,baseUrl) <- viewRealmAndUrl
  let opts = W.defaults
  let url = (unpack $ baseUrl <> "/realms/" <> realm <> "/" <> path) 
  info $ "Issuing KEYCLOAK POST with url: " ++ (show url) 
  debug $ "  data: " ++ (show dat) 
  --debug $ "  headers: " ++ (show $ opts ^. W.headers) 
  eRes <- liftIO $ C.try $ W.postWith opts url dat
  case eRes of 
    Right res -> do
      return $ fromJust $ res ^? responseBody
    Left er -> do
      warn $ "Keycloak HTTP error: " ++ (show er)
      kcError $ HTTPError er

-- | Perform delete to Keycloak.
keycloakDelete :: MonadIO m => Path -> JWT -> KeycloakT m ()
keycloakDelete path jwt = do 
  (realm,baseUrl) <- viewRealmAndUrl
  let opts = W.defaults & W.header "Authorization" .~ ["Bearer " <> (convertString $ encodeCompact jwt)]
  let url = (unpack $ baseUrl <> "/realms/" <> realm <> "/" <> path) 
  info $ "Issuing KEYCLOAK DELETE with url: " ++ (show url) 
  debug $ "  headers: " ++ (show $ opts ^. W.headers) 
  eRes <- liftIO $ C.try $ W.deleteWith opts url
  case eRes of 
    Right _ -> return ()
    Left er -> do
      warn $ "Keycloak HTTP error: " ++ (show er)
      kcError $ HTTPError er

-- | Perform get to Keycloak on admin API
keycloakGet :: MonadIO m => Path -> JWT -> KeycloakT m BL.ByteString
keycloakGet path tok = do
  (realm,baseUrl) <- viewRealmAndUrl
  let opts = W.defaults & W.header "Authorization" .~ ["Bearer " <> (convertString $ encodeCompact tok)]
  let url = (unpack $ baseUrl <> "/realms/" <> realm <> "/" <> path) 
  info $ "Issuing KEYCLOAK GET with url: " ++ (show url) 
  debug $ "  headers: " ++ (show $ opts ^. W.headers) 
  eRes <- liftIO $ C.try $ W.getWith opts url
  case eRes of 
    Right res -> do
      return $ fromJust $ res ^? responseBody
    Left er -> do
      warn $ "Keycloak HTTP error: " ++ (show er)
      kcError $ HTTPError er

-- | Perform get to Keycloak on admin API, without token
keycloakGet' :: MonadIO m => Path -> KeycloakT m BL.ByteString
keycloakGet' path = do
  (realm,baseUrl) <- viewRealmAndUrl
  let opts = W.defaults
  let url = (unpack $ baseUrl <> "/realms/" <> realm <> "/" <> path) 
  info $ "Issuing KEYCLOAK GET with url: " ++ (show url) 
  debug $ "  headers: " ++ (show $ opts ^. W.headers) 
  eRes <- liftIO $ C.try $ W.getWith opts url
  case eRes of
    Right res -> do
      return $ fromJust $ res ^? responseBody
    Left er -> do
      warn $ "Keycloak HTTP error: " ++ (show er)
      kcError $ HTTPError er


-- | Perform get to Keycloak on admin API
keycloakAdminGet :: MonadIO m => Path -> JWT -> KeycloakT m BL.ByteString
keycloakAdminGet path tok = do 
  (realm,baseUrl) <- viewRealmAndUrl
  let opts = W.defaults & W.header "Authorization" .~ ["Bearer " <> (convertString $ encodeCompact tok)]
  let url = (unpack $ baseUrl <> "/admin/realms/" <> realm <> "/" <> path) 
  info $ "Issuing KEYCLOAK GET with url: " ++ (show url) 
  debug $ "  headers: " ++ (show $ opts ^. W.headers) 
  eRes <- liftIO $ C.try $ W.getWith opts url
  case eRes of 
    Right res -> do
      return $ fromJust $ res ^? responseBody
    Left er -> do
      warn $ "Keycloak HTTP error: " ++ (show er)
      kcError $ HTTPError er

-- | Perform post to Keycloak.
keycloakAdminPost :: (Postable dat, Show dat, MonadIO m) => Path -> dat -> JWT -> KeycloakT m BL.ByteString
keycloakAdminPost path dat tok = do 
  (realm,baseUrl) <- viewRealmAndUrl
  let opts = W.defaults & W.header "Authorization" .~ ["Bearer " <> (convertString $ encodeCompact tok)]
  let url = (unpack $ baseUrl <> "/admin/realms/" <> realm <> "/" <> path) 
  info $ "Issuing KEYCLOAK POST with url: " ++ (show url) 
  debug $ "  data: " ++ (show dat) 
  --debug $ "  headers: " ++ (show $ opts ^. W.headers) 
  eRes <- liftIO $ C.try $ W.postWith opts url dat
  case eRes of 
    Right res -> do
      debug $ (show eRes)
      let hs = fromJust $ res ^? W.responseHeaders
      return $ convertString $ L.last $ T.split (== '/') $ convertString $ fromJust $ lookup "Location" hs
    Left er -> do
      warn $ "Keycloak HTTP error: " ++ (show er)
      kcError $ HTTPError er

-- | Perform put to Keycloak.
keycloakAdminPut :: (Putable dat, Show dat, MonadIO m) => Path -> dat -> JWT -> KeycloakT m ()
keycloakAdminPut path dat tok = do 
  (realm,baseUrl) <- viewRealmAndUrl
  let opts = W.defaults & W.header "Authorization" .~ ["Bearer " <> (convertString $ encodeCompact tok)]
  let url = (unpack $ baseUrl <> "/admin/realms/" <> realm <> "/" <> path) 
  info $ "Issuing KEYCLOAK PUT with url: " ++ (show url) 
  debug $ "  data: " ++ (show dat) 
  debug $ "  headers: " ++ (show $ opts ^. W.headers) 
  eRes <- liftIO $ C.try $ W.putWith opts url dat
  case eRes of 
    Right _ -> return ()
    Left er -> do
      warn $ "Keycloak HTTP error: " ++ (show er)
      kcError $ HTTPError er

kcError :: Monad m => KCError -> KeycloakT m a
kcError = KeycloakT . throwError

viewRealmAndUrl :: Monad m => KeycloakT m (Realm,ServerURL)
viewRealmAndUrl = do
  realm <- viewConfig (confAdapterConfig.confRealm)
  baseUrl <- viewConfig (confAdapterConfig.confAuthServerUrl)
  pure (realm,baseUrl)

viewConfig :: Monad m => Getting b KCConfig b -> KeycloakT m b
viewConfig = KeycloakT . view

-- * Helpers

debug, warn, info, err :: MonadIO m => String -> m ()
debug s = liftIO $ debugM "Keycloak" s
info s  = liftIO $ infoM "Keycloak" s
warn s  = liftIO $ warningM "Keycloak" s
err s   = liftIO $ errorM "Keycloak" s

getErrorStatus :: KCError -> Maybe Status 
getErrorStatus (HTTPError (HttpExceptionRequest _ (StatusCodeException r _))) = Just $ HC.responseStatus r
getErrorStatus _ = Nothing

try :: Monad m => KeycloakT m b -> KeycloakT m (Either KCError b)
try (KeycloakT act) = KeycloakT $ catchError (Right <$> act) (return . Left)
