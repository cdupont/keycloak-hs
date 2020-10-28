{-# LANGUAGE OverloadedStrings #-}

module Main where

import Keycloak
import Control.Monad
import Control.Monad.IO.Class
import System.Log.Logger


-- Kecyloak configuration.
kcConfig :: KCConfig
kcConfig = KCConfig {
  _confBaseUrl       = "http://localhost:8080/auth",
  _confRealm         = "demo",
  _confClientId      = "demo",
  _confClientSecret  = "3d792576-4e56-4c58-991a-49074e6a92ea"}

main :: IO ()
main = do
  updateGlobalLogger rootLoggerName (setLevel DEBUG)

  void $ flip runKeycloak kcConfig $ do
    liftIO $ putStrLn "Starting tests..."
  
    -- JWKs are public keys delivered by Keycloak to check the integrity of any JWT (user tokens).
    -- an application may retrieve these keys at startup and keep them.
    jwks <- getJWKs
    liftIO $ putStrLn $ "Got JWKs: \n" ++ (show jwks) ++ "\n\n"
  
    -- Get a JWT from Keycloak. A JWT can then be used to authentify yourself with an application.
    jwt <- getJWT "demo" "demo" 
    liftIO $ putStrLn $ "Got JWT: \n" ++ (show jwt) ++ "\n\n"
  
    -- Retrieve the claims contained in the JWT.
    claims <- verifyJWT (head jwks) jwt
    liftIO $ putStrLn $ "Claims decoded from Token: \n" ++ (show claims) ++ "\n\n"
    
    -- get the user from the claim
    let user = getClaimsUser claims
    liftIO $ putStrLn $ "User decoded from claims: \n" ++ (show user) ++ "\n\n"
  
  
    liftIO $ putStrLn "Getting Client token"
  
    -- * We first get a client token, used to create resources 
    clientToken <- getClientJWT
  
    liftIO $ putStrLn "Creating resource"
  
    -- * We will than create a resource to be protected in Keycloak
    let res = Resource {
           resId      = Nothing,
           resName    = "MyResource",
           resType    = Nothing,
           resUris    = [],
           resScopes  = [Scope Nothing (ScopeName "view")],
           resOwner   = Owner Nothing (Just "demo"),
           resOwnerManagedAccess = False,
           resAttributes = []}
    resId <- createResource res clientToken  
  
    liftIO $ putStrLn "Getting User token"
  
    -- * Let's get a token for a specific user
    userToken <- getJWT "demo" "demo"
  
    -- * Can I access this resource?
    isAuth <- isAuthorized resId (ScopeName "view") userToken
  
    liftIO $ putStrLn $ "User 'demo' can access resource 'demo': " ++ (show isAuth)
  
    -- We can also retrieve all the permissions for our user.
    perms <- getPermissions [PermReq Nothing [ScopeName "view"]] userToken
  
    liftIO $ putStrLn $ "All permissions: " ++ (show perms)
  
    --resources can be deleted
    --deleteResource resId clientToken
