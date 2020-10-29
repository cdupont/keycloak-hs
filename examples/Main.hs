{-# LANGUAGE OverloadedStrings #-}

module Main where

import Keycloak
import Control.Monad
import Control.Monad.IO.Class
import System.Log.Logger


main :: IO ()
main = do
  -- Keycloak-hs has logging, you can enable it for debugging.
  updateGlobalLogger rootLoggerName (setLevel DEBUG)

  -- Read the Keycloak config file. You can retrieve this file in your Client/Installation tab (JSON format).
  kcConfig <- configureKeycloak "keycloak.json"
  putStrLn $ "Loaded Keycloak config: " ++ (show kcConfig)
  -- We run all the commands in the 'Keycloak' Monad.
  void $ flip runKeycloak kcConfig $ do
    liftIO $ putStrLn "Starting tests..."
  
    -- Get a JWT from Keycloak. A JWT can then be used to authentify yourself with an application.
    jwt <- getJWT "demo" "demo" 
    liftIO $ putStrLn $ "Got JWT: \n" ++ (show jwt) ++ "\n\n"
  
    -- Retrieve the claims contained in the JWT.
    claims <- verifyJWT jwt
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
    --perms <- getPermissions [PermReq Nothing [ScopeName "view"]] userToken
  
    --liftIO $ putStrLn $ "All permissions: " ++ (show perms)
  
    --resources can be deleted
    --deleteResource resId clientToken

    users <- getUsers Nothing Nothing Nothing jwt
    liftIO $ putStrLn $ "All Users: " ++ (show users)
