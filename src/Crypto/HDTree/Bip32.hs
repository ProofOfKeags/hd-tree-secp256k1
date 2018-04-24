{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
module Crypto.HDTree.Bip32 
    ( ckdDiagHardened
    , ckdDiagStandard
    , ckdPriv
    , ckdPub
    , neuter
    , toAddress
    , derivePath
    , ChainCode(..)
    , Index(..)
    , XPub(..)
    ) where

import           Basement.Types.Word256 (Word256(..))
import           Control.Monad (unless)
import           Crypto.Hash (hashWith)
import           Crypto.Hash.Algorithms
import           Crypto.MAC.HMAC
import           Crypto.Secp256k1
import qualified Data.ByteArray as BA
import           Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Base58 as B58
import           Data.Monoid
import           Data.Serialize
import           Data.Serialize.Put
import           Data.Serialize.Get
import           Data.Word (Word8, Word32)

newtype ChainCode = ChainCode { getChainCode :: Word256 }
    deriving (Eq)
newtype Index = Index { getIndex :: Word32 }

data XPub = XPub {
    xPubDepth :: Word8,
    xPubFingerprintPar :: Word32,
    xPubChildNumber :: Word32,
    xPubChainCode :: ChainCode,
    xPubPubKey :: PubKey
}
        deriving (Eq)

data XPriv = XPriv {
    xPrivDepth :: Word8,
    xPrivFingerprintPar :: Word32,
    xPrivChildNumber :: Word32,
    xPrivChainCode :: ChainCode,
    xPrivPrivKey :: SecKey
}

xpubMagicMain = 0x0488B21E
xpubMagicTest = 0x043587CF
xprivMagicMain = 0x0488ADE4
xprivMagicTest = 0x04358394


ser32 :: Word32 -> ByteString
ser32 = runPut . putWord32be

ser256 :: Word256 -> ByteString
ser256 (Word256 a b c d) = runPut . mconcat . fmap putWord64be $ [a, b, c, d]

serP :: PubKey -> ByteString
serP = exportPubKey True

-- parses 256 bit bytestring into a 256 bit integer
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

-- ckdPriv spec: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#private-parent-key--private-child-key
ckdPriv :: SecKey -> ChainCode -> Index -> Maybe (SecKey, ChainCode)
ckdPriv sPar cPar idx
    | getIndex idx >= 0x80000000 = go hardened
    | otherwise                  = go standard
    where
        hardened = hmac (ser256 $ getChainCode cPar) ("\x00" <> getSecKey sPar <> ser32 (getIndex idx))
        standard = hmac (ser256 $ getChainCode cPar) (serP (derivePubKey sPar) <> ser32 (getIndex idx))
        go :: HMAC SHA512 -> Maybe (SecKey, ChainCode)
        go hash = do
            let i = BA.convert $ hmacGetDigest hash
                il = BS.take 32 i
                ir = BS.take 32 . BS.drop 32 $ i
            si <- tweak il >>= tweakAddSecKey sPar
            ci <- ChainCode <$> parse256 ir
            return (si, ci)

-- ckdPub spec: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#public-parent-key--public-child-key
ckdPub :: PubKey -> ChainCode -> Index -> Maybe (PubKey, ChainCode)
ckdPub kPar cPar idx
    | getIndex idx >= 0x80000000 = Nothing
    | otherwise                  = go standard
    where
        standard = hmac (ser256 $ getChainCode cPar) (serP kPar <> ser32 (getIndex idx))
        go :: HMAC SHA512 -> Maybe (PubKey, ChainCode)
        go hash = do
            let i = BA.convert $ hmacGetDigest hash
                il = BS.take 32 i
                ir = BS.take 32 . BS.drop 32 $ i
            kToAdd <- derivePubKey <$> secKey il
            ki <- combinePubKeys [kPar, kToAdd]
            ci <- ChainCode <$> parse256 ir
            return (ki, ci)


neuter :: SecKey -> ChainCode -> (PubKey, ChainCode)
neuter sPar cPar = (derivePubKey sPar, cPar)

ckdDiagStandard :: SecKey -> ChainCode -> Index -> Maybe (PubKey, ChainCode)
ckdDiagStandard sPar cPar idx = if getIndex idx >= 0x80000000
    then Nothing
    else uncurry ckdPub (neuter sPar cPar) idx

ckdDiagHardened :: SecKey -> ChainCode -> Index -> Maybe (PubKey, ChainCode)
ckdDiagHardened sPar cPar = fmap (uncurry neuter) . ckdPriv sPar cPar

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

instance Serialize PubKey where
    put = putByteString . serP
    get = do
        bytes <- getBytes 33
        case importPubKey bytes of
            Nothing -> fail "get: pub key import failed"
            Just x -> return x

instance Serialize SecKey where
    put = putByteString . ("\x00"<>) . getSecKey
    get = do
        bytes <- getBytes 33
        case secKey $ BS.drop 1 bytes of
            Nothing -> fail "get: priv key import failed"
            Just x -> return x

instance Serialize XPub where
    put k = do
        putWord32be xpubMagicMain
        putWord8 $ xPubDepth k
        putWord32be $ xPubFingerprintPar k
        putWord32be $ xPubChildNumber k
        put $ xPubChainCode k
        put $ xPubPubKey k
    get = do
        version <- getWord32be
        unless (version == xpubMagicMain || version == xpubMagicTest)
            (fail "get: wrong version bytes")
        xPubDepth <- getWord8
        xPubFingerprintPar <- getWord32be
        xPubChildNumber <- getWord32be
        xPubChainCode <- get
        xPubPubKey <- get
        return XPub{..}

instance Serialize XPriv where
    put k = do
        putWord32be xprivMagicMain
        putWord8 $ xPrivDepth k
        putWord32be $ xPrivFingerprintPar k
        putWord32be $ xPrivChildNumber k
        put $ xPrivChainCode k
        put '\x00'
        put $ xPrivPrivKey k
    get = do
        version <- getWord32be
        unless (version == xprivMagicMain || version == xprivMagicTest)
            (fail "get: wrong version bytes")
        xPrivDepth <- getWord8
        xPrivFingerprintPar <- getWord32be
        xPrivChildNumber <- getWord32be
        xPrivChainCode <- get
        xPrivPrivKey <- get
        return XPriv{..}

instance Show XPub where
    show = B8.unpack . encode

toAddress :: XPub -> ByteString 
toAddress xpub =
    let 
        b58 = B58.encodeBase58 B58.bitcoinAlphabet 
        sha256 = hashWith SHA256
        checksum = BS.take 4 . BA.convert . sha256 . BA.convert . sha256 $ encode xpub
    in
        b58 $ encode xpub <> checksum

fromAddress :: ByteString -> Maybe XPub
fromAddress addr =
    let
        b58 = B58.decodeBase58 B58.bitcoinAlphabet
    in
        b58 addr >>= \x -> case decode . BS.take 78 $ x of
            Left e -> Nothing
            Right a -> Just a

newtype Path = Path { unPath :: [Index] }
        
derivePathPub :: Seed -> Path -> XPub
derivePathPub = _

derivePathPriv :: Seed -> Path -> XPriv
derivePathPriv = _

{-
testPubKey = case importPubKey $ BS.pack (0x03 : (replicate 32 0xFE)) of
    Nothing -> undefined
    Just x -> x

testXPub = XPub {
    xPubDepth = 0xFF,
    xPubFingerprintPar = 0xFFFFFFFF,
    xPubChildNumber = 0xFFFFFFFF,
    xPubChainCode = ChainCode (Word256 0xFFFFFFFFFFFFFFFF 0xFFFFFFFFFFFFFFFF  0xFFFFFFFFFFFFFFFF  0xFFFFFFFFFFFFFFFF),
    xPubPubKey = testPubKey
}
-}