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
    , toXAddress
    , fromXAddress
    , derivePathPriv
    , derivePathPub
    , derivePublicKey
    , deriveRootPriv
    , deriveRootPub
    , getCompressed
    , getUncompressed
    , getXCoord
    , getYCoord
    , hash160
    , hash256
    , mkPrivKey
    , mkPubKey
    , parsePath
    , ChainCode(..)
    , Extended(..)
    , increment
    , Index(..)
    , Path(..)
    , PrivateKey(..)
    , PublicKey(..)
    , Seed(..)
    , XPriv
    , XPub
    )
where

import           Control.Lens            hiding ( Index
                                                , index
                                                , indices
                                                )
import           Crypto.Hash                    ( hashWith
                                                , Digest
                                                )
import           Crypto.Hash.Algorithms
import           Crypto.MAC.HMAC
import qualified Data.ByteArray                as BA
import           Data.ByteString                ( ByteString )
import qualified Data.ByteString               as BS
import qualified Data.ByteString.Base58        as B58
import           Data.Either                    ( fromRight )
import           Data.Monoid
import           Data.Serialize
import           Data.Word                      ( Word32 )

import           Crypto.HDTree.Bip32.DerivationPath
import           Crypto.HDTree.Bip32.ExtendedKeys

-- tests to see whether the index is a hardened index or not
isHardened :: Index -> Bool
isHardened = (>= 0x80000000) . getIndex

-- ckdPriv spec: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#private-parent-key--private-child-key
ckdPriv :: PrivateKey -> ChainCode -> Index -> Maybe (PrivateKey, ChainCode)
ckdPriv sPar cPar idx | isHardened idx = go hardened
                      | otherwise      = go standard
  where
    hardened = hmac (ser256 $ getChainCode cPar) ("\x00" <> getPrivKey sPar <> ser32 (getIndex idx))
    standard = hmac (ser256 $ getChainCode cPar) (serP (derivePublicKey sPar) <> ser32 (getIndex idx))
    go :: HMAC SHA512 -> Maybe (PrivateKey, ChainCode)
    go hash = do
        let i  = BA.convert $ hmacGetDigest hash
            il = BS.take 32 i
            ir = BS.take 32 . BS.drop 32 $ i
        si <- tweakAddPrivateKey sPar il
        ci <- ChainCode <$> parse256 ir
        return (si, ci)

-- ckdPub spec: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#public-parent-key--public-child-key
ckdPub :: PublicKey -> ChainCode -> Index -> Maybe (PublicKey, ChainCode)
ckdPub kPar cPar idx | isHardened idx = Nothing
                     | otherwise      = go standard
  where
    standard = hmac (ser256 $ getChainCode cPar) (serP kPar <> ser32 (getIndex idx))
    go :: HMAC SHA512 -> Maybe (PublicKey, ChainCode)
    go hash = do
        let i  = BA.convert $ hmacGetDigest hash
            il = BS.take 32 i
            ir = BS.take 32 . BS.drop 32 $ i
        kToAdd <- derivePublicKey <$> mkPrivKey il
        ki     <- addPublicKeys kPar kToAdd
        ci     <- ChainCode <$> parse256 ir
        return (ki, ci)

neuter :: XPriv -> XPub
neuter = over extKey derivePublicKey

ckdDiagStandard :: PrivateKey -> ChainCode -> Index -> Maybe (PublicKey, ChainCode)
ckdDiagStandard sPar cPar idx = if isHardened idx then Nothing else ckdPub (derivePublicKey sPar) cPar idx

ckdDiagHardened :: PrivateKey -> ChainCode -> Index -> Maybe (PublicKey, ChainCode)
ckdDiagHardened sPar cPar = fmap (_1 %~ derivePublicKey) . ckdPriv sPar cPar

toXAddress :: (MagicMain s, Serialize s) => Extended s -> ByteString
toXAddress xpub =
    let b58      = B58.encodeBase58 B58.bitcoinAlphabet
        checksum = BS.take 4 . BA.convert . hash256 $ encode xpub
    in  b58 $ encode xpub <> checksum

fromXAddress :: (MagicMain s, Serialize s) => ByteString -> Maybe (Extended s)
fromXAddress addr =
    let b58 = B58.decodeBase58 B58.bitcoinAlphabet
    in  b58 addr >>= \x -> case decode . BS.take 78 $ x of
            Left  _ -> Nothing
            Right a -> Just a

deriveRootPub :: Seed -> Maybe XPub
deriveRootPub = fmap (extKey %~ derivePublicKey) . deriveRootPriv

deriveRootPriv :: Seed -> Maybe XPriv
deriveRootPriv (Seed seed) =
    let seedLength            = BS.length seed
        key                   = "Bitcoin seed" :: ByteString
        h                     = hmac key $ seed :: HMAC SHA512
        bytes                 = BA.convert h
        il                    = BS.take 32 bytes
        ir                    = BS.take 32 $ BS.drop 32 bytes
        _extDepth             = 0
        _extParentFingerprint = 0
        _extChildNumber       = 0
    in  if seedLength < 16 || seedLength > 64
            then Nothing
            else do
                _extChainCode <- ChainCode <$> parse256 ir
                _extKey       <- mkPrivKey il
                return Extended { .. }

-- Recursive Derivation via ckdPub and ckdPriv
derivePathPub :: XPub -> Path -> Maybe XPub
derivePathPub xp (Path []      ) = Just xp
derivePathPub xp (Path (i : is)) = if isHardened i
    then Nothing
    else
        let incDepth             = extDepth %~ (+ 1)
            setParentFingerprint = extParentFingerprint .~ fingerprint (xp ^. extKey)
            setChildNumber       = extChildNumber .~ getIndex i
        in  do
                (k, c) <- ckdPub (xp ^. extKey) (xp ^. extChainCode) i
                let xp' = incDepth . setParentFingerprint . setChildNumber . set extKey k . set extChainCode c $ xp
                derivePathPub xp' (Path is)

derivePathPriv :: XPriv -> Path -> Maybe XPriv
derivePathPriv xp (Path []) = Just xp
derivePathPriv xp (Path (i : is)) =
    let incDepth             = extDepth %~ (+ 1)
        setParentFingerprint = extParentFingerprint .~ fingerprint (derivePublicKey $ xp ^. extKey)
        setChildNumber       = extChildNumber .~ getIndex i
    in  do
            (k, c) <- ckdPriv (xp ^. extKey) (xp ^. extChainCode) i
            let xp' = incDepth . setParentFingerprint . setChildNumber . set extKey k . set extChainCode c $ xp
            derivePathPriv xp' (Path is)

hash160 :: ByteString -> Digest RIPEMD160
hash160 = hashWith RIPEMD160 . hashWith SHA256

hash256 :: ByteString -> Digest SHA256
hash256 = hashWith SHA256 . hashWith SHA256

fingerprint :: PublicKey -> Word32
fingerprint = fromRight err . decode . BS.take 4 . BA.convert . hash160 . encode where err = error "unreachable"
