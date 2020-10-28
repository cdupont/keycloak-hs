{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE ViewPatterns #-}

module Keycloak.Tokens where

import           Control.Lens hiding ((.=))
import           Control.Monad.Reader as R
import           Control.Monad.Except (throwError)
import           Crypto.JWT as JWT
import           Data.Aeson as JSON
import           Data.Aeson.Lens
import           Data.Text as T hiding (head, tail, map)
import           Data.Maybe
import qualified Data.HashMap.Strict as HM
import           Data.String.Conversions
import           Keycloak.Types
import           Keycloak.Utils
import           Network.Wreq as W hiding (statusCode)

-- * Tokens

-- | return JWKs from Keycloak. Its a set of keys that can be used to check signed tokens (JWTs)
getJWKs :: Keycloak [JWK]
getJWKs = do
  body <- keycloakGet' ("protocol/openid-connect/certs")
  info $ show body
  (JWKSet jwks) <- case eitherDecode body of
     Right ret -> do
       return ret
     Left (err2 :: String) -> do
       debug $ "Keycloak parse error: " ++ (show err2) 
       throwError $ ParseError $ pack (show err2)
  return jwks


-- | Retrieve the user's token. This token can be used for every other Keycloak calls.
getJWT :: Username -> Password -> Keycloak JWT
getJWT username password = do 
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
      decodeCompact $ convertString $ accessToken ret
    Left err2 -> do
      debug $ "Keycloak parse error: " ++ (show err2) 
      throwError $ ParseError $ pack (show err2)

-- | return a Client token (linked to a Client, not a User). It is useful to create Resources in that Client in Keycloak.
getClientJWT :: Keycloak JWT
getClientJWT = do
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
      decodeCompact $ convertString $ accessToken ret
    Left err2 -> do
      debug $ "Keycloak parse error: " ++ (show err2) 
      throwError $ ParseError $ pack (show err2)


-- | Verify a JWT. If sucessful, the claims are returned. Otherwise, a JWTError is thrown. 
verifyJWT :: JWK -> JWT -> Keycloak ClaimsSet
verifyJWT jwk jwt = verifyClaims (defaultJWTValidationSettings (const True)) jwk jwt

-- | Extract the user identity from a token. Additional attributes can be encoded in the token.
getClaimsUser :: ClaimsSet -> User
getClaimsUser claims = User { userId          = Just $ UserId $ view (claimSub . _Just . string) claims
                            , userUsername    = view (unregisteredClaims . at "preferred_username" . _Just . _String) claims
                            , userFirstName   = preview (unregisteredClaims . at "given_name" . _Just . _String) claims
                            , userLastName    = preview (unregisteredClaims . at "family_name" . _Just . _String) claims
                            , userEmail       = preview (unregisteredClaims . at "email" . _Just . _String) claims
                            , userAttributes  = preview unregisteredClaims claims}


