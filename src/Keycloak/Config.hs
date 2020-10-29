{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE ViewPatterns #-}

module Keycloak.Config where

import           Data.Aeson as JSON
import qualified Data.ByteString.Lazy as BL
import           Keycloak.Types
import           Keycloak.Tokens

-- | Read a configuration file.
-- This file can be found in Keycloak, in the Client Installation tab (JSON format).
readConfig :: FilePath -> IO AdapterConfig
readConfig f = do
  j <- BL.readFile f
  case eitherDecode j of
    Right c -> return c
    Left e -> error e

-- | Configure this library by reading the adapter JSON file, and getting signing keys from Keycloak.
-- The returned config can be used with 'runKeycloak' to run any function living in the 'Keycloak' Monad.
configureKeycloak :: FilePath -> IO KCConfig
configureKeycloak f = do
  adapterConf <- readConfig f
  jwks <- getJWKs (_confRealm adapterConf) (_confAuthServerUrl adapterConf)
  return $ KCConfig adapterConf jwks


