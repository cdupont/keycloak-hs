{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ViewPatterns #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE TemplateHaskell #-}

module Keycloak.Types where

import           Data.Aeson
import           Data.Aeson.Types
import           Data.Aeson.Casing
import           Data.Text hiding (head, tail, map, toLower, drop)
import           Data.Text.Encoding
import           Data.Monoid
import           Data.String.Conversions
import           Data.Maybe
import           Data.Map hiding (drop, map)
import qualified Data.ByteString as BS
import qualified Data.Word8 as W8 (isSpace, _colon, toLower)
import           Data.Char
import           Control.Monad.Except (ExceptT, runExceptT)
import           Control.Monad.Reader as R
import           Control.Lens hiding ((.=))
import           GHC.Generics (Generic)
import           Web.HttpApiData (FromHttpApiData(..), ToHttpApiData(..))
import           Network.HTTP.Client as HC hiding (responseBody)
import           Web.JWT as JWT

-- * Keycloak Monad

-- | Keycloak Monad stack: a simple Reader monad containing the config, and an ExceptT to handle HTTPErrors and parse errors.
type Keycloak a = ReaderT KCConfig (ExceptT KCError IO) a

-- | Contains HTTP errors and parse errors.
data KCError = HTTPError HttpException  -- ^ Keycloak returned an HTTP error.
             | ParseError Text          -- ^ Failed when parsing the response
             | EmptyError               -- ^ Empty error to serve as a zero element for Monoid.

-- | Configuration of Keycloak.
data KCConfig = KCConfig {
  _baseUrl       :: Text,
  _realm         :: Text,
  _clientId      :: Text,
  _clientSecret  :: Text} deriving (Eq, Show)

-- | Default configuration
defaultKCConfig :: KCConfig
defaultKCConfig = KCConfig {
  _baseUrl       = "http://localhost:8080/auth",
  _realm         = "waziup",
  _clientId      = "api-server",
  _clientSecret  = "4e9dcb80-efcd-484c-b3d7-1e95a0096ac0"}

-- | Run a Keycloak monad within IO.
runKeycloak :: Keycloak a -> KCConfig -> IO (Either KCError a)
runKeycloak kc conf = runExceptT $ runReaderT kc conf

type Path = Text


-- * Token

-- | Wrapper for tokens.
newtype Token = Token {unToken :: BS.ByteString} deriving (Eq, Show, Generic)

instance ToJSON Token where
  toJSON (Token t) = String $ convertString t

-- | parser for Authorization header
instance FromHttpApiData Token where
  parseQueryParam = parseHeader . encodeUtf8
  parseHeader (extractBearerAuth -> Just tok) = Right $ Token tok
  parseHeader _ = Left "cannot extract auth Bearer"

extractBearerAuth :: BS.ByteString -> Maybe BS.ByteString
extractBearerAuth bs =
    let (x, y) = BS.break W8.isSpace bs
    in if BS.map W8.toLower x == "bearer"
        then Just $ BS.dropWhile W8.isSpace y
        else Nothing

-- | Create Authorization header
instance ToHttpApiData Token where
  toQueryParam (Token token) = "Bearer " <> (decodeUtf8 token)
 
-- | Keycloak Token additional claims
tokNonce, tokAuthTime, tokSessionState, tokAtHash, tokCHash, tokName, tokGivenName, tokFamilyName, tokMiddleName, tokNickName, tokPreferredUsername, tokProfile, tokPicture, tokWebsite, tokEmail, tokEmailVerified, tokGender, tokBirthdate, tokZoneinfo, tokLocale, tokPhoneNumber, tokPhoneNumberVerified,tokAddress, tokUpdateAt, tokClaimsLocales, tokACR :: Text
tokNonce               = "nonce";
tokAuthTime            = "auth_time";
tokSessionState        = "session_state";
tokAtHash              = "at_hash";
tokCHash               = "c_hash";
tokName                = "name";
tokGivenName           = "given_name";
tokFamilyName          = "family_name";
tokMiddleName          = "middle_name";
tokNickName            = "nickname";
tokPreferredUsername   = "preferred_username";
tokProfile             = "profile";
tokPicture             = "picture";
tokWebsite             = "website";
tokEmail               = "email";
tokEmailVerified       = "email_verified";
tokGender              = "gender";
tokBirthdate           = "birthdate";
tokZoneinfo            = "zoneinfo";
tokLocale              = "locale";
tokPhoneNumber         = "phone_number";
tokPhoneNumberVerified = "phone_number_verified";
tokAddress             = "address";
tokUpdateAt            = "updated_at";
tokClaimsLocales       = "claims_locales";
tokACR                 = "acr";

-- | Token reply from Keycloak
data TokenRep = TokenRep {
  accessToken       :: JWT.JSON,
  expiresIn         :: Int,
  refreshExpriresIn :: Int,
  refreshToken      :: JWT.JSON,
  tokenType         :: Text,
  notBeforePolicy   :: Int,
  sessionState      :: Text,
  scope             :: Text} deriving (Show, Eq)

instance FromJSON TokenRep where
  parseJSON (Object v) = TokenRep <$> v .: "access_token"
                                  <*> v .: "expires_in"
                                  <*> v .: "refresh_expires_in"
                                  <*> v .: "refresh_token"
                                  <*> v .: "token_type"
                                  <*> v .: "not-before-policy"
                                  <*> v .: "session_state"
                                  <*> v .: "scope"

-- * Permission

-- | Scope name
type ScopeName = Text

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

-- | Keycloak permission on a resource
data Permission = Permission 
  { rsname :: ResourceName,
    rsid   :: ResourceId,
    scopes :: [ScopeName]
  } deriving (Generic, Show, Eq)

instance ToJSON Permission where
  toJSON = genericToJSON defaultOptions {omitNothingFields = True}

instance FromJSON Permission where
  parseJSON = genericParseJSON defaultOptions


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
  { userId        :: Maybe UserId   -- ^ The unique user ID 
  , userUsername  :: Username       -- ^ Username
  , userFirstName :: Maybe Text     -- ^ First name
  , userLastName  :: Maybe Text     -- ^ Last name
  , userEmail     :: Maybe Text     -- ^ Email
  , userAttributes :: Maybe (Map Text [Text]) 
  } deriving (Show, Eq, Generic)

unCapitalize :: String -> String
unCapitalize (c:cs) = toLower c : cs
unCapitalize [] = []

instance FromJSON User where
  parseJSON = genericParseJSON defaultOptions {fieldLabelModifier = unCapitalize . drop 4}

instance ToJSON User where
  toJSON = genericToJSON defaultOptions {fieldLabelModifier = unCapitalize . drop 4, omitNothingFields = True}



-- * Owner

-- | A resource owner
data Owner = Owner {
  ownId   :: Maybe Text,
  ownName :: Username
  } deriving (Generic, Show)

instance FromJSON Owner where
  parseJSON = genericParseJSON $ aesonDrop 3 snakeCase 

instance ToJSON Owner where
  toJSON = genericToJSON $ (aesonDrop 3 snakeCase) {omitNothingFields = True}


-- * Resource

type ResourceName = Text

-- | A resource Id
newtype ResourceId = ResourceId {unResId :: Text} deriving (Show, Eq, Generic)

-- JSON instances
instance ToJSON ResourceId where
  toJSON = genericToJSON (defaultOptions {unwrapUnaryRecords = True})

instance FromJSON ResourceId where
  parseJSON = genericParseJSON (defaultOptions {unwrapUnaryRecords = True})

-- | A complete resource
data Resource = Resource {
     resId                 :: Maybe ResourceId,
     resName               :: ResourceName,
     resType               :: Maybe Text,
     resUris               :: [Text],
     resScopes             :: [Scope],
     resOwner              :: Owner,
     resOwnerManagedAccess :: Bool,
     resAttributes         :: [Attribute]
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
    return $ Resource rId rName rType rUris rScopes rOwn rOMA (maybe [] fromJust rAtt)

instance ToJSON Resource where
  toJSON (Resource id name typ uris scopes own uma attrs) =
    object ["name"               .= toJSON name,
            "uris"               .= toJSON uris,
            "scopes"             .= toJSON scopes,
            "owner"              .= (toJSON $ ownName own),
            "ownerManagedAccess" .= toJSON uma,
            "attributes"         .= object (map (\(Attribute name vals) -> name .= toJSON vals) attrs)]

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
