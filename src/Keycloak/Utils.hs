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
keycloakPost :: (Postable dat, Show dat) => Path -> dat -> JWT -> Keycloak BL.ByteString
keycloakPost path dat jwt = do
  realm <- view (confAdapterConfig.confRealm)
  baseUrl <- view (confAdapterConfig.confAuthServerUrl)
  let opts = W.defaults & W.header "Authorization" .~ ["Bearer " <> (convertString $ encodeCompact jwt)]
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
  realm <- view (confAdapterConfig.confRealm)
  baseUrl <- view (confAdapterConfig.confAuthServerUrl)
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
keycloakDelete :: Path -> JWT -> Keycloak ()
keycloakDelete path jwt = do 
  realm <- view (confAdapterConfig.confRealm)
  baseUrl <- view (confAdapterConfig.confAuthServerUrl)
  let opts = W.defaults & W.header "Authorization" .~ ["Bearer " <> (convertString $ encodeCompact jwt)]
  let url = (unpack $ baseUrl <> "/realms/" <> realm <> "/" <> path) 
  info $ "Issuing KEYCLOAK DELETE with url: " ++ (show url) 
  debug $ "  headers: " ++ (show $ opts ^. W.headers) 
  eRes <- C.try $ liftIO $ W.deleteWith opts url
  case eRes of 
    Right _ -> return ()
    Left er -> do
      warn $ "Keycloak HTTP error: " ++ (show er)
      throwError $ HTTPError er

-- | Perform get to Keycloak on admin API
keycloakGet :: Path -> JWT -> Keycloak BL.ByteString
keycloakGet path tok = do 
  realm <- view (confAdapterConfig.confRealm)
  baseUrl <- view (confAdapterConfig.confAuthServerUrl)
  let opts = W.defaults & W.header "Authorization" .~ ["Bearer " <> (convertString $ encodeCompact tok)]
  let url = (unpack $ baseUrl <> "/realms/" <> realm <> "/" <> path) 
  info $ "Issuing KEYCLOAK GET with url: " ++ (show url) 
  debug $ "  headers: " ++ (show $ opts ^. W.headers) 
  eRes <- C.try $ liftIO $ W.getWith opts url
  case eRes of 
    Right res -> do
      return $ fromJust $ res ^? responseBody
    Left er -> do
      warn $ "Keycloak HTTP error: " ++ (show er)
      throwError $ HTTPError er

-- | Perform get to Keycloak on admin API, without token
keycloakGet' :: Path -> Keycloak BL.ByteString
keycloakGet' path = do 
  realm <- view (confAdapterConfig.confRealm)
  baseUrl <- view (confAdapterConfig.confAuthServerUrl)
  let opts = W.defaults
  let url = (unpack $ baseUrl <> "/realms/" <> realm <> "/" <> path) 
  info $ "Issuing KEYCLOAK GET with url: " ++ (show url) 
  debug $ "  headers: " ++ (show $ opts ^. W.headers) 
  eRes <- C.try $ liftIO $ W.getWith opts url
  case eRes of 
    Right res -> do
      return $ fromJust $ res ^? responseBody
    Left er -> do
      warn $ "Keycloak HTTP error: " ++ (show er)
      throwError $ HTTPError er


-- | Perform get to Keycloak on admin API
keycloakAdminGet :: Path -> JWT -> Keycloak BL.ByteString
keycloakAdminGet path tok = do 
  realm <- view (confAdapterConfig.confRealm)
  baseUrl <- view (confAdapterConfig.confAuthServerUrl)
  let opts = W.defaults & W.header "Authorization" .~ ["Bearer " <> (convertString $ encodeCompact tok)]
  let url = (unpack $ baseUrl <> "/admin/realms/" <> realm <> "/" <> path) 
  info $ "Issuing KEYCLOAK GET with url: " ++ (show url) 
  debug $ "  headers: " ++ (show $ opts ^. W.headers) 
  eRes <- C.try $ liftIO $ W.getWith opts url
  case eRes of 
    Right res -> do
      return $ fromJust $ res ^? responseBody
    Left er -> do
      warn $ "Keycloak HTTP error: " ++ (show er)
      throwError $ HTTPError er

-- | Perform post to Keycloak.
keycloakAdminPost :: (Postable dat, Show dat) => Path -> dat -> JWT -> Keycloak BL.ByteString
keycloakAdminPost path dat tok = do 
  realm <- view (confAdapterConfig.confRealm)
  baseUrl <- view (confAdapterConfig.confAuthServerUrl)
  let opts = W.defaults & W.header "Authorization" .~ ["Bearer " <> (convertString $ encodeCompact tok)]
  let url = (unpack $ baseUrl <> "/admin/realms/" <> realm <> "/" <> path) 
  info $ "Issuing KEYCLOAK POST with url: " ++ (show url) 
  debug $ "  data: " ++ (show dat) 
  --debug $ "  headers: " ++ (show $ opts ^. W.headers) 
  eRes <- C.try $ liftIO $ W.postWith opts url dat
  case eRes of 
    Right res -> do
      debug $ (show eRes)
      let hs = fromJust $ res ^? W.responseHeaders
      return $ convertString $ L.last $ T.split (== '/') $ convertString $ fromJust $ lookup "Location" hs
    Left er -> do
      warn $ "Keycloak HTTP error: " ++ (show er)
      throwError $ HTTPError er

-- | Perform put to Keycloak.
keycloakAdminPut :: (Putable dat, Show dat) => Path -> dat -> JWT -> Keycloak ()
keycloakAdminPut path dat tok = do 
  realm <- view (confAdapterConfig.confRealm)
  baseUrl <- view (confAdapterConfig.confAuthServerUrl)
  let opts = W.defaults & W.header "Authorization" .~ ["Bearer " <> (convertString $ encodeCompact tok)]
  let url = (unpack $ baseUrl <> "/admin/realms/" <> realm <> "/" <> path) 
  info $ "Issuing KEYCLOAK PUT with url: " ++ (show url) 
  debug $ "  data: " ++ (show dat) 
  debug $ "  headers: " ++ (show $ opts ^. W.headers) 
  eRes <- C.try $ liftIO $ W.putWith opts url dat
  case eRes of 
    Right _ -> return ()
    Left er -> do
      warn $ "Keycloak HTTP error: " ++ (show er)
      throwError $ HTTPError er


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



