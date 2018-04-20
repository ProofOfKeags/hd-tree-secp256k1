{-# LANGUAGE OverloadedStrings #-}
module Crypto.HDTree.Bip32 
    ( ckdDiag
    , ckdPriv
    , ckdPub
    , ChainCode(..)
    , Index(..)
    , XPub(..)
    ) where

import           Basement.Types.Word256 (Word256(..))
import           Crypto.Hash.Algorithms
import           Crypto.MAC.HMAC
import           Crypto.Secp256k1
import qualified Data.ByteArray as BA
import           Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import           Data.Monoid
import           Data.Serialize.Put
import           Data.Serialize.Get
import           Data.Word (Word32)

newtype ChainCode = ChainCode { getChainCode :: Word256 }
newtype Index = Index { getIndex :: Word32 }

data XPub = XPub PubKey ChainCode

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


ckdDiag :: SecKey -> ChainCode -> (PubKey, ChainCode)
ckdDiag = _
