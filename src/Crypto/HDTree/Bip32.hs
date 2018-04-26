{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TemplateHaskell #-}
module Crypto.HDTree.Bip32 
    ( ckdDiagHardened
    , ckdDiagStandard
    , ckdPriv
    , ckdPub
    , neuter
    , toAddress
    , fromAddress
    , derivePathPriv
    , derivePathPub
    , deriveRootPriv
    , deriveRootPub
    , parsePath
    , ChainCode(..)
    , Index(..)
    , Path(..)
    , Seed(..)
    ) where

import           Basement.Types.Word256 (Word256(..))
import           Control.Applicative ((<|>))
import           Control.Lens hiding (Index, index, indices)
import           Control.Monad (unless)
import           Crypto.Hash (hashWith, Digest)
import           Crypto.Hash.Algorithms
import           Crypto.MAC.HMAC
import qualified Crypto.Secp256k1 as SECP
import           Crypto.Secp256k1 (Tweak, tweak)
import qualified Data.ByteArray as BA
import           Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Base58 as B58
import           Data.Either (fromRight)
import           Data.Monoid
import           Data.Serialize
import           Data.Word (Word8, Word32)
import           Text.Trifecta hiding (err)

import Crypto.HDTree.Constants

newtype PublicKey = PublicKey { pubKey :: SECP.PubKey }
newtype PrivateKey = PrivateKey { privKey :: SECP.SecKey }

getPrivKey :: PrivateKey -> ByteString
getPrivKey = SECP.getSecKey . privKey

derivePublicKey :: PrivateKey -> PublicKey
derivePublicKey = PublicKey . SECP.derivePubKey . privKey

tweakAddPrivateKey :: PrivateKey -> Tweak -> Maybe PrivateKey
tweakAddPrivateKey p t = fmap PrivateKey . SECP.tweakAddSecKey (privKey p) $ t

mkPubKey :: ByteString -> Maybe PublicKey
mkPubKey = fmap PublicKey . SECP.importPubKey

mkPrivKey :: ByteString -> Maybe PrivateKey
mkPrivKey = fmap PrivateKey . SECP.secKey

addPublicKeys :: PublicKey -> PublicKey -> Maybe PublicKey
addPublicKeys a b = PublicKey <$> SECP.combinePubKeys [pubKey a, pubKey b]


newtype ChainCode = ChainCode { getChainCode :: Word256 }
    deriving (Eq, Show)
newtype Index = Index { getIndex :: Word32 }

instance Show Index where
    show (Index i) =
        if i >= 0x80000000
            then show (i - 0x80000000) ++ "'"
            else show i

type XPub = Extended PublicKey
type XPriv = Extended PrivateKey
data Extended a = Extended
    { _extDepth :: Word8
    , _extParentFingerprint :: Word32
    , _extChildNumber :: Word32
    , _extChainCode :: ChainCode
    , _extKey :: a
    }
makeLenses ''Extended

class MagicMain a where
    magicMain :: a -> Word32

instance MagicMain PublicKey where
    magicMain _ = xpubMagicMain

instance MagicMain PrivateKey where
    magicMain _ = xprivMagicMain

instance MagicMain a => MagicMain (Extended a) where
    magicMain = magicMain . _extKey

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

isHardened :: Index -> Bool
isHardened = (>= 0x80000000) . getIndex

-- ckdPriv spec: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#private-parent-key--private-child-key
ckdPriv :: PrivateKey -> ChainCode -> Index -> Maybe (PrivateKey, ChainCode)
ckdPriv sPar cPar idx
    | getIndex idx >= 0x80000000 = go hardened
    | otherwise                  = go standard
    where
        hardened = hmac (ser256 $ getChainCode cPar) ("\x00" <> getPrivKey sPar <> ser32 (getIndex idx))
        standard = hmac (ser256 $ getChainCode cPar) (serP (derivePublicKey sPar) <> ser32 (getIndex idx))
        go :: HMAC SHA512 -> Maybe (PrivateKey, ChainCode)
        go hash = do
            let i = BA.convert $ hmacGetDigest hash
                il = BS.take 32 i
                ir = BS.take 32 . BS.drop 32 $ i
            si <- tweak il >>= tweakAddPrivateKey sPar
            ci <- ChainCode <$> parse256 ir
            return (si, ci)

-- ckdPub spec: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#public-parent-key--public-child-key
ckdPub :: PublicKey -> ChainCode -> Index -> Maybe (PublicKey, ChainCode)
ckdPub kPar cPar idx
    | getIndex idx >= 0x80000000 = Nothing
    | otherwise                  = go standard
    where
        standard = hmac (ser256 $ getChainCode cPar) (serP kPar <> ser32 (getIndex idx))
        go :: HMAC SHA512 -> Maybe (PublicKey, ChainCode)
        go hash = do
            let i = BA.convert $ hmacGetDigest hash
                il = BS.take 32 i
                ir = BS.take 32 . BS.drop 32 $ i
            kToAdd <- derivePublicKey <$> mkPrivKey il
            ki <- addPublicKeys kPar kToAdd
            ci <- ChainCode <$> parse256 ir
            return (ki, ci)

neuter :: XPriv -> XPub
neuter = over extKey derivePublicKey

ckdDiagStandard :: PrivateKey -> ChainCode -> Index -> Maybe (PublicKey, ChainCode)
ckdDiagStandard sPar cPar idx = if getIndex idx >= 0x80000000
    then Nothing
    else ckdPub (derivePublicKey sPar) cPar idx

ckdDiagHardened :: PrivateKey -> ChainCode -> Index -> Maybe (PublicKey, ChainCode)
ckdDiagHardened sPar cPar = fmap (_1 %~ derivePublicKey) . ckdPriv sPar cPar

newtype Seed = Seed { getSeed :: ByteString }

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
            (fail "get: wrong version bytes")
        _extDepth <- getWord8
        _extParentFingerprint <- getWord32be
        _extChildNumber <- getWord32be
        _extChainCode <- get
        _extKey <- get
        return $ Extended{..}

instance Show XPub where
    show = B8.unpack . encode

toAddress :: (Serialize s) => s -> ByteString 
toAddress xpub =
    let 
        b58 = B58.encodeBase58 B58.bitcoinAlphabet 
        sha256 = hashWith SHA256
        checksum = BS.take 4 . BA.convert . sha256 . BA.convert . sha256 $ encode xpub
    in
        b58 $ encode xpub <> checksum

fromAddress :: (Serialize s) => ByteString -> Maybe s
fromAddress addr =
    let
        b58 = B58.decodeBase58 B58.bitcoinAlphabet
    in
        b58 addr >>= \x -> case decode . BS.take 78 $ x of
            Left _ -> Nothing
            Right a -> Just a

newtype Path = Path { privPath :: [Index] }

instance Show Path where
    show = ('m':) . ((('/':) . show) =<<) . privPath

parsePath :: String -> Maybe Path
parsePath s = case parseString path mempty s of
    Success a -> Just a
    _ -> Nothing

path :: Parser Path
path = do
    _ <- char 'm'
    privPath <- (indexList <|> (const [] <$> eof))
    return Path{..}

indexList :: Parser [Index]
indexList = do
    _ <- char '/'
    (Index idx) <- index
    offset <- option 0 $ const 0x80000000 <$> char '\''
    rest <- indexList <|> (const [] <$> eof)
    return $ (Index $ idx + offset):rest

index :: Parser Index
index = Index . fromIntegral <$> decimal

deriveRootPub :: Seed -> Maybe XPub
deriveRootPub = fmap (extKey %~ derivePublicKey) . deriveRootPriv 

deriveRootPriv :: Seed -> Maybe XPriv
deriveRootPriv (Seed seed) =
    let
        seedLength = BS.length seed
        key = "Bitcoin seed" :: ByteString
        h = hmac key $ seed :: HMAC SHA512
        bytes = BA.convert h
        il = BS.take 32 bytes
        ir = BS.take 32 $ BS.drop 32 bytes
        _extDepth = 0
        _extParentFingerprint = 0
        _extChildNumber = 0
    in 
        if seedLength < 16 || seedLength > 64
            then Nothing
            else do
                _extChainCode <- ChainCode <$> parse256 ir
                _extKey <- mkPrivKey il
                return Extended{..}

hash160 :: ByteString -> Digest RIPEMD160
hash160 = hashWith RIPEMD160 . (BA.convert :: Digest SHA256 -> ByteString) . hashWith SHA256

fingerprint :: PublicKey -> Word32
fingerprint = fromRight err . decode . BS.take 4 . BA.convert . hash160 . encode 
    where err = error "unreachable"

derivePathPub :: XPub -> Path -> Maybe XPub
derivePathPub xp (Path []) = Just xp
derivePathPub xp (Path (i:is)) = if isHardened i
    then Nothing
    else 
        let 
            incDepth = extDepth %~ (+1)
            setParentFingerprint = extParentFingerprint .~ fingerprint (xp ^. extKey)
            setChildNumber = extChildNumber .~ getIndex i
        in do
            (k, c) <- ckdPub (xp ^. extKey) (xp ^. extChainCode) i
            let xp' = incDepth . setParentFingerprint . setChildNumber . set extKey k . set extChainCode c $ xp
            derivePathPub xp' (Path is)

derivePathPriv :: XPriv -> Path -> Maybe XPriv
derivePathPriv xp (Path []) = Just xp
derivePathPriv xp (Path (i:is)) =
    let
        incDepth = extDepth %~ (+1)
        setParentFingerprint = extParentFingerprint .~ fingerprint (derivePublicKey $ xp ^. extKey)
        setChildNumber = extChildNumber .~ getIndex i
    in do
        (k, c) <- ckdPriv (xp ^. extKey) (xp ^. extChainCode) i
        let xp' = incDepth . setParentFingerprint . setChildNumber . set extKey k . set extChainCode c $ xp
        derivePathPriv xp' (Path is)
