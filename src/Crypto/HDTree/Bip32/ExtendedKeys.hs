{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TemplateHaskell #-}
module Crypto.HDTree.Bip32.ExtendedKeys where

import           Basement.Types.Word256 (Word256(..))
import           Control.Lens hiding (Index, index)
import           Control.Monad (unless)
import qualified Crypto.Secp256k1 as SECP
import           Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import           Data.Monoid ((<>))
import           Data.Serialize
import           Data.Word (Word8, Word32)
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Char8 as B8

import Crypto.HDTree.Bip32.Constants

newtype Seed = Seed { getSeed :: ByteString }
newtype PublicKey = PublicKey { pubKey :: SECP.PubKey } deriving (Eq, Show)
newtype PrivateKey = PrivateKey { privKey :: SECP.SecKey } deriving (Eq, Show)

getXCoord :: PublicKey -> ByteString
getXCoord = BS.take 32 . BS.drop 1 . getUncompressed
getYCoord :: PublicKey -> ByteString
getYCoord = BS.drop 33 . getUncompressed
getUncompressed :: PublicKey -> ByteString
getUncompressed = SECP.exportPubKey False . pubKey
getCompressed :: PublicKey -> ByteString
getCompressed = SECP.exportPubKey True . pubKey

newtype ChainCode = ChainCode { getChainCode :: Word256 }
    deriving (Eq, Show)

data Extended a = Extended
    { _extDepth :: Word8
    , _extParentFingerprint :: Word32
    , _extChildNumber :: Word32
    , _extChainCode :: ChainCode
    , _extKey :: a
    }
    deriving (Eq, Show)
makeLenses ''Extended

type XPub = Extended PublicKey
type XPriv = Extended PrivateKey

instance Serialize ChainCode where
    put = putByteString . ser256 . getChainCode
    get = do
        n <- Word256
            <$> getWord64be
            <*> getWord64be
            <*> getWord64be
            <*> getWord64be
        return $ ChainCode n

instance Serialize PublicKey where
    put = putByteString . serP
    get = do
        bytes <- getBytes 33
        case mkPubKey bytes of
            Nothing -> fail "get: pub key import failed"
            Just x -> return x

instance Serialize PrivateKey where
    put = putByteString . ("\x00"<>) . getPrivKey
    get = do
        bytes <- getBytes 33
        case mkPrivKey $ BS.drop 1 bytes of
            Nothing -> fail "get: priv key import failed"
            Just x -> return x

-- serializes 32 bit unsigned integer to big endian represented 4 byte bytestring
ser32 :: Word32 -> ByteString
ser32 = runPut . putWord32be

-- serializes 256 bit unsigned integer to big endian represented 32 byte bytestring
ser256 :: Word256 -> ByteString
ser256 (Word256 a b c d) = runPut . mconcat . fmap putWord64be $ [a, b, c, d]

-- serializes public key to 33 byte bytestring
serP :: PublicKey -> ByteString
serP = SECP.exportPubKey True . pubKey

-- parses 256 bit bytestring into a 256 bit unsigned integer
parse256 :: ByteString -> Maybe Word256
parse256 bs =
    let g = (,)
            <$> (Word256
                <$> getWord64be
                <*> getWord64be
                <*> getWord64be
                <*> getWord64be)
            <*> isEmpty
    in case runGet g bs of
            Left _ -> Nothing
            Right (result, empty) -> if empty 
                then Just result 
                else Nothing

getPrivKey :: PrivateKey -> ByteString
getPrivKey = SECP.getSecKey . privKey

derivePublicKey :: PrivateKey -> PublicKey
derivePublicKey = PublicKey . SECP.derivePubKey . privKey

tweakAddPrivateKey :: PrivateKey -> ByteString -> Maybe PrivateKey
tweakAddPrivateKey p t = fmap PrivateKey . SECP.tweakAddSecKey (privKey p) =<< SECP.tweak t

mkPubKey :: ByteString -> Maybe PublicKey
mkPubKey = fmap PublicKey . SECP.importPubKey

mkPrivKey :: ByteString -> Maybe PrivateKey
mkPrivKey = fmap PrivateKey . SECP.secKey

addPublicKeys :: PublicKey -> PublicKey -> Maybe PublicKey
addPublicKeys a b = PublicKey <$> SECP.combinePubKeys [pubKey a, pubKey b]

class MagicMain a where
    magicMain :: a -> Word32

instance MagicMain PublicKey where
    magicMain _ = xpubMagicMain

instance MagicMain PrivateKey where
    magicMain _ = xprivMagicMain

instance MagicMain a => MagicMain (Extended a) where
    magicMain = magicMain . _extKey

instance (MagicMain a, Serialize a) => Serialize (Extended a) where
    put k = do
        putWord32be $ magicMain k
        putWord8 $ k ^. extDepth
        putWord32be $ k ^. extParentFingerprint
        putWord32be $ k ^. extChildNumber
        put $ k ^. extChainCode
        put $ k ^. extKey
    get = do
        version <- getWord32be
        unless (version == xpubMagicMain || version == xprivMagicMain)
            (fail $ "get: wrong version bytes: " <> B8.unpack (B16.encode (encode version)))
        _extDepth <- getWord8
        _extParentFingerprint <- getWord32be
        _extChildNumber <- getWord32be
        _extChainCode <- get
        _extKey <- get
        return $ Extended{..}