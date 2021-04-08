{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE ViewPatterns #-}

-- |
-- Authentication with Keycloak is based on [JWTs](https://jwt.io/).
-- This module helps you retrieve tokens from Keycloak, and use them to authenticate your users.
-- In Keycloak, you need to configure a realm, a client and a user.
-- 
-- Users can also have additional attributes.
-- To see them in the Token, you need to add "protocol mappers" in the Client, that will copy the User attribute in the Token.
-- 
-- The example below retrieves a User token using Login/password, verifies it, and extract all the user details from it.
-- 
-- @
-- main :: IO ()
-- main = do
-- 
--   --configure Keycloak with the adapter config file. You can retrieve this file in your Client/Installation tab (JSON format).
--   --This function will also get the signing keys from Keycloak, so make sure that Keycloak is on and configured!
--   kcConfig <- configureKeycloak "keycloak.json"
--
--   void $ flip runKeycloak kcConfig $ do
--   
--     -- Get a JWT from Keycloak. A JWT can then be used to authenticate yourself with an application.
--     jwt <- getJWT "demo" "demo" 
--     liftIO $ putStrLn $ "Got JWT: \n" ++ (show jwt) ++ "\n\n"
--   
--     -- Retrieve the claims contained in the JWT.
--     claims <- verifyJWT jwt
--     liftIO $ putStrLn $ "Claims decoded from Token: \n" ++ (show claims) ++ "\n\n"
--     
--     -- get the user from the claim
--     let user = getClaimsUser claims
--     liftIO $ putStrLn $ "User decoded from claims: \n" ++ (show user) ++ "\n\n"
-- @

module Keycloak.Tokens where

import           Control.Lens hiding ((.=))
import           Control.Monad.IO.Class
import           Control.Monad.Time (MonadTime)
import           Crypto.JWT as JWT
import           Data.Aeson as JSON
import           Data.Aeson.Lens
import           Data.Text as T hiding (head, tail, map)
import           Data.Maybe
import           Data.String.Conversions
import           Keycloak.Types
import           Keycloak.Utils
import           Network.Wreq as W hiding (statusCode)



-- | Retrieve the user's token. This token can be used to authenticate the user.
-- This token can be also used for every other Keycloak calls.
getJWT :: MonadIO m => Username -> Password ->  KeycloakT m JWT
getJWT username password = do
  debug "Get user token"
  client <- viewConfig $ confAdapterConfig.confResource
  secret <- viewConfig $ confAdapterConfig.confCredentials.confSecret
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
      KeycloakT $ decodeCompact $ convertString $ accessToken ret
    Left err2 -> do
      debug $ "Keycloak parse error: " ++ (show err2) 
      kcError $ ParseError $ pack (show err2)

-- | return a Client token (linked to a Client, not a User). It is useful to create Resources in that Client in Keycloak.
getClientJWT :: MonadIO m => KeycloakT m JWT
getClientJWT = do
  debug "Get client token"
  client <- viewConfig $ confAdapterConfig.confResource
  secret <- viewConfig $ confAdapterConfig.confCredentials.confSecret
  let dat = ["client_id" := client, 
             "client_secret" := secret,
             "grant_type" := ("client_credentials" :: Text)]
  body <- keycloakPost' "protocol/openid-connect/token" dat
  case eitherDecode body of
    Right ret -> do
      debug $ "Keycloak success: " ++ (show ret) 
      KeycloakT $ decodeCompact $ convertString $ accessToken ret
    Left err2 -> do
      debug $ "Keycloak parse error: " ++ (show err2) 
      kcError $ ParseError $ pack (show err2)


-- | Verify a JWT. If sucessful, the claims are returned. Otherwise, a JWTError is thrown. 
verifyJWT :: (MonadTime m, MonadIO m) => JWT -> KeycloakT m ClaimsSet
verifyJWT jwt = do
  jwks <- viewConfig confJWKs
  KeycloakT $ verifyClaims (defaultJWTValidationSettings (const True)) (head jwks) jwt

-- | Extract the user identity from a token. Additional attributes can be encoded in the token.
getClaimsUser :: ClaimsSet -> User
getClaimsUser claims = User { userId          = Just $ UserId $ view (claimSub . _Just . string) claims
                            , userUsername    = view (unregisteredClaims . at "preferred_username" . _Just . _String) claims
                            , userFirstName   = preview (unregisteredClaims . at "given_name" . _Just . _String) claims
                            , userLastName    = preview (unregisteredClaims . at "family_name" . _Just . _String) claims
                            , userEmail       = preview (unregisteredClaims . at "email" . _Just . _String) claims
                            , userAttributes  = preview unregisteredClaims claims}


-- | return JWKs from Keycloak. Its a set of keys that can be used to check signed tokens (JWTs)
-- This is done for you in the 'configureKeycloak' function. JWKs are stored in the Keycloak State Monad.
getJWKs :: Realm -> ServerURL -> IO [JWK]
getJWKs realm baseUrl = do
  let opts = W.defaults
  let url = unpack (baseUrl <> "/realms/" <> realm <> "/protocol/openid-connect/certs")
  info $ "Issuing KEYCLOAK GET with url: " ++ show url
  debug $ "  headers: " ++ show (opts ^. W.headers)
  res <- W.getWith opts url
  let body = fromJust $ res ^? responseBody
  info $ show body
  case eitherDecode body of
     Right (JWKSet jwks) -> return jwks
     Left (err2 :: String) -> do
       debug $ "Keycloak parse error: " ++ show err2
       error $ show err2
