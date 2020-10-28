{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE DeriveAnyClass #-}

module Keycloak.Types where

import           Data.Aeson
import           Data.Aeson.Casing
import           Data.Hashable
import           Data.Text hiding (head, tail, map, toLower, drop)
import           Data.String.Conversions
import           Data.Maybe
import           Data.Map hiding (drop, map)
import qualified Data.HashMap.Strict as HM
import           Data.Char
import           Control.Monad.Except (ExceptT, runExceptT)
import           Control.Monad.Reader as R
import           Control.Lens hiding ((.=))
import           GHC.Generics (Generic)
import           Network.HTTP.Client as HC hiding (responseBody)
import           Crypto.JWT as JWT

-- | Our Json Web Token as returned by Keycloak
type JWT = SignedJWT

-- * Keycloak Monad

-- | Keycloak Monad stack: a simple Reader monad containing the config, and an ExceptT to handle HTTPErrors and parse errors.
-- You can extract the value using 'runKeycloak'.
-- Example: @keys <- runKeycloak getJWKs defaultKCConfig@
type Keycloak a = ReaderT KCConfig (ExceptT KCError IO) a

-- | Contains HTTP errors and parse errors.
data KCError = HTTPError HttpException  -- ^ Keycloak returned an HTTP error.
             | ParseError Text          -- ^ Failed when parsing the response
             | JWTError JWTError        -- ^ Failed to decode the token
             | EmptyError               -- ^ Empty error to serve as a zero element for Monoid.
             deriving (Show)

instance AsJWTError KCError where
  _JWTError = prism' JWTError up where
    up (JWTError e) = Just e
    up _ = Nothing

instance AsError KCError where
  _Error = _JWSError


-- | Configuration of Keycloak.
data KCConfig = KCConfig {
  _confBaseUrl       :: Text,  -- ^ Base url where Keycloak resides
  _confRealm         :: Text,  -- ^ realm to use
  _confClientId      :: Text,  -- ^ client id
  _confClientSecret  :: Text}  -- ^ client secret, found in Client/Credentials tab
  deriving (Eq, Show)

-- | Default configuration
defaultKCConfig :: KCConfig
defaultKCConfig = KCConfig {
  _confBaseUrl       = "http://localhost:8080/auth",
  _confRealm         = "waziup",
  _confClientId      = "api-server",
  _confClientSecret  = "4e9dcb80-efcd-484c-b3d7-1e95a0096ac0"}

-- | Run a Keycloak monad within IO.
runKeycloak :: Keycloak a -> KCConfig -> IO (Either KCError a)
runKeycloak kc conf = runExceptT $ runReaderT kc conf

type Path = Text


-- * Token

-- | Token reply from Keycloak
data TokenRep = TokenRep {
  accessToken       :: Text,
  expiresIn         :: Int,
  refreshExpriresIn :: Int,
  refreshToken      :: Text,
  tokenType         :: Text,
  notBeforePolicy   :: Int,
  sessionState      :: Text,
  tokenScope        :: Text} deriving (Show, Eq)

instance FromJSON TokenRep where
  parseJSON (Object v) = TokenRep <$> v .: "access_token"
                                  <*> v .: "expires_in"
                                  <*> v .: "refresh_expires_in"
                                  <*> v .: "refresh_token"
                                  <*> v .: "token_type"
                                  <*> v .: "not-before-policy"
                                  <*> v .: "session_state"
                                  <*> v .: "scope"
  parseJSON _ = error "Not an object"

-- * Permissions

-- | Scope name, such as "houses:view"
-- You need to create the scopes in Client/Authorization panel/Authorization scopes tab
newtype ScopeName = ScopeName {unScopeName :: Text} deriving (Eq, Generic, Ord, Hashable)

--JSON instances
instance ToJSON ScopeName where
  toJSON = genericToJSON (defaultOptions {unwrapUnaryRecords = True})

instance FromJSON ScopeName where
  parseJSON = genericParseJSON (defaultOptions {unwrapUnaryRecords = True})

instance Show ScopeName where
  show (ScopeName s) = convertString s

-- | Scope Id
newtype ScopeId = ScopeId {unScopeId :: Text} deriving (Show, Eq, Generic)

--JSON instances
instance ToJSON ScopeId where
  toJSON = genericToJSON (defaultOptions {unwrapUnaryRecords = True})

instance FromJSON ScopeId where
  parseJSON = genericParseJSON (defaultOptions {unwrapUnaryRecords = True})

-- | Keycloak scope
data Scope = Scope {
  scopeId   :: Maybe ScopeId,
  scopeName :: ScopeName
  } deriving (Generic, Show, Eq)

instance ToJSON Scope where
  toJSON = genericToJSON defaultOptions {fieldLabelModifier = unCapitalize . drop 5, omitNothingFields = True}

instance FromJSON Scope where
  parseJSON = genericParseJSON defaultOptions {fieldLabelModifier = unCapitalize . drop 5}

-- | permission request
-- You can perform a request on a specific resourse, or on all resources.
-- You can request permission on multiple scopes at once.
-- 
data PermReq = PermReq 
  { permReqResourceId :: Maybe ResourceId, -- ^ Requested ressource Ids. Nothing means "All resources".
    permReqScopes     :: [ScopeName]       -- ^ Scopes requested. [] means "all scopes".
  } deriving (Generic, Eq, Ord, Hashable)

instance Show PermReq where
  show (PermReq (Just (ResourceId res1)) scopes) = (show res1) <> " " <> (show scopes)
  show (PermReq Nothing scopes)                  = "none " <> (show scopes)

-- | Keycloak permission on a resource
-- Returned by Keycloak after a permission request is made.
-- 
data Permission = Permission 
  { permRsid   :: Maybe ResourceId,   -- ^ Resource ID, can be Nothing in case of scope-only permission request
    permRsname :: Maybe ResourceName, -- ^ Resource Name, can be Nothing in case of scope-only permission request
    permScopes :: [ScopeName]         -- ^ Scopes that are accessible (Non empty)
  } deriving (Generic, Show, Eq)

instance ToJSON Permission where
  toJSON = genericToJSON defaultOptions {fieldLabelModifier = unCapitalize . drop 4, omitNothingFields = True}

instance FromJSON Permission where
  parseJSON = genericParseJSON defaultOptions {fieldLabelModifier = unCapitalize . drop 4}



-- * User

type Username = Text
type Password = Text
type First = Int
type Max = Int

-- | Id of a user
newtype UserId = UserId {unUserId :: Text} deriving (Show, Eq, Generic)

--JSON instances
instance ToJSON UserId where
  toJSON = genericToJSON (defaultOptions {unwrapUnaryRecords = True})

instance FromJSON UserId where
  parseJSON = genericParseJSON (defaultOptions {unwrapUnaryRecords = True})

-- | User 
data User = User
  { userId         :: Maybe UserId   -- ^ The unique user ID 
  , userUsername   :: Username       -- ^ Username
  , userFirstName  :: Maybe Text     -- ^ First name
  , userLastName   :: Maybe Text     -- ^ Last name
  , userEmail      :: Maybe Text     -- ^ Email
  , userAttributes :: Maybe (HM.HashMap Text Value)
  } deriving (Show, Eq, Generic)

unCapitalize :: String -> String
unCapitalize (a:as) = toLower a : as
unCapitalize [] = []

instance FromJSON User where
  parseJSON = genericParseJSON defaultOptions {fieldLabelModifier = unCapitalize . drop 4}

instance ToJSON User where
  toJSON = genericToJSON defaultOptions {fieldLabelModifier = unCapitalize . drop 4, omitNothingFields = True}



-- * Owner

-- | A resource owner
data Owner = Owner {
  ownId   :: Maybe Text,
  ownName :: Maybe Username
  } deriving (Generic, Show)

instance FromJSON Owner where
  parseJSON = genericParseJSON $ aesonDrop 3 snakeCase 

instance ToJSON Owner where
  toJSON = genericToJSON $ (aesonDrop 3 snakeCase) {omitNothingFields = True}


-- * Resource

type ResourceName = Text
type ResourceType = Text

-- | A resource Id
newtype ResourceId = ResourceId {unResId :: Text} deriving (Show, Eq, Generic, Ord, Hashable)

-- JSON instances
instance ToJSON ResourceId where
  toJSON = genericToJSON (defaultOptions {unwrapUnaryRecords = True})

instance FromJSON ResourceId where
  parseJSON = genericParseJSON (defaultOptions {unwrapUnaryRecords = True})

-- | A complete resource
-- Resources are created in Keycloak in Client/
-- You can create resources in Client/Authorization panel/Resources scopes tab
data Resource = Resource {
     resId                 :: Maybe ResourceId,   -- ^ the Keycloak resource ID
     resName               :: ResourceName,       -- ^ the Keycloak resource name
     resType               :: Maybe ResourceType, -- ^ Optional resource type
     resUris               :: [Text],             -- ^ Optional resource URI
     resScopes             :: [Scope],            -- ^ All the possible scopes for that resource
     resOwner              :: Owner,              -- ^ The Owner or the resource
     resOwnerManagedAccess :: Bool,               -- ^ Whether the owner can manage his own resources (e.g. resource sharing with others)
     resAttributes         :: [Attribute]         -- ^ Resource attributes
  } deriving (Generic, Show)

instance FromJSON Resource where
  parseJSON (Object v) = do
    rId     <- v .:? "_id"
    rName   <- v .:  "name"
    rType   <- v .:? "type"
    rUris   <- v .:  "uris"
    rScopes <- v .:  "scopes"
    rOwn    <- v .:  "owner"
    rOMA    <- v .:  "ownerManagedAccess"
    rAtt    <- v .:? "attributes"
    let atts = if isJust rAtt then toList $ fromJust rAtt else []
    return $ Resource rId rName rType rUris rScopes rOwn rOMA (map (\(a, b) -> Attribute a b) atts)
  parseJSON _ = error "not an object"

instance ToJSON Resource where
  toJSON (Resource rid name typ uris scopes own uma attrs) =
    object ["_id"                .= toJSON rid,
            "name"               .= toJSON name,
            "type"               .= toJSON typ,
            "uris"               .= toJSON uris,
            "scopes"             .= toJSON scopes,
            "owner"              .= (toJSON $ ownName own),
            "ownerManagedAccess" .= toJSON uma,
            "attributes"         .= object (map (\(Attribute aname vals) -> aname .= toJSON vals) attrs)]

-- | A resource attribute
data Attribute = Attribute {
  attName   :: Text,
  attValues :: [Text]
  } deriving (Generic, Show)

instance FromJSON Attribute where
  parseJSON = genericParseJSON $ aesonDrop 3 camelCase 

instance ToJSON Attribute where
  toJSON (Attribute name vals) = object [name .= toJSON vals] 



makeLenses ''KCConfig
