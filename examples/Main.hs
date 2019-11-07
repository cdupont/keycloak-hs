{-# LANGUAGE OverloadedStrings #-}

module Main where

import Keycloak
import Control.Monad
import Control.Monad.IO.Class

-- Kecyloak configuration.
kcConfig :: KCConfig
kcConfig = KCConfig {
  _baseUrl       = "http://localhost:8080/auth",
  _realm         = "demo",
  _clientId      = "demo",
  _clientSecret  = "4270ce82-4a8f-4d89-9ea9-d9b28c3bab3e"}

main :: IO ()
main = void $ flip runKeycloak kcConfig $ do
  
  liftIO $ putStrLn "Getting Client token"

  -- * We first get a client token 
  clientToken <- getClientAuthToken

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
  userToken <- getUserAuthToken "demo" "demo"

  -- * Can I access this resource?
  isAuth <- isAuthorized resId (ScopeName "view") userToken

  liftIO $ putStrLn $ "User 'demo' can access resource 'demo': " ++ (show isAuth)

  -- We can also retrieve all the permissions for our user.
  perms <- getPermissions [PermReq Nothing [ScopeName "view"]] userToken

  liftIO $ putStrLn $ "All permissions: " ++ (show perms)

  --resources can be deleted
  --deleteResource resId clientToken
