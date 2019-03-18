{-# LANGUAGE NoMonomorphismRestriction #-}
{-# LANGUAGE OverloadedStrings #-}
module Crypto.HDTree.Address where

import           Crypto.HDTree.Bip32
import           Crypto.Hash
import           Control.Applicative
import           Data.Bits
import           Data.ByteString                ( ByteString )
import qualified Data.ByteString               as BS
import qualified Data.ByteString.Char8         as B8
import qualified Data.ByteString.Base16        as B16
import qualified Data.ByteString.Base58        as B58
import qualified Data.ByteArray                as BA
import           Data.Char
import           Data.List
import           Data.Monoid
import           Data.Serialize
import           Data.Word

newtype EthAddr = EthAddr { unEthAddr :: ByteString } deriving (Eq)
instance Show EthAddr where
    show e = "0x" <> (B8.unpack . unEthAddr $ e)
instance Read EthAddr where
    readsPrec i s = filter (isValidEthAddr . fst) [(EthAddr (BS.drop 2 x), y) | (x, y) <- readsPrec i s]

newtype BtcAddr = BtcAddr { unBtcAddr :: ByteString } deriving (Eq)
instance Show BtcAddr where
    show = B8.unpack . unBtcAddr
instance Read BtcAddr where
    readsPrec i s = filter (isValidBtcAddr . fst) [(BtcAddr x, y) | (x, y) <- readsPrec i s]

newtype LtcAddr = LtcAddr { unLtcAddr :: ByteString } deriving (Eq)
instance Show LtcAddr where
    show = B8.unpack . unLtcAddr
instance Read LtcAddr where
    readsPrec i s = filter (isValidLtcAddr . fst) [(LtcAddr x, y) | (x, y) <- readsPrec i s]

newtype DogeAddr = DogeAddr { unDogeAddr :: ByteString } deriving (Eq)
instance Show DogeAddr where
    show = B8.unpack . unDogeAddr
instance Read DogeAddr where
    readsPrec i s = filter (isValidDogeAddr . fst) [(DogeAddr x, y) | (x, y) <- readsPrec i s]

newtype DashAddr = DashAddr { unDashAddr :: ByteString } deriving (Eq)
instance Show DashAddr where
    show = B8.unpack . unDashAddr
instance Read DashAddr where
    readsPrec i s = filter (isValidDashAddr . fst) [(DashAddr x, y) | (x, y) <- readsPrec i s]

getEthAddress :: PublicKey -> EthAddr
getEthAddress = ethChecksum . getLowerEthAddress

bitAt :: Int -> ByteString -> Bool
bitAt i = bitIndex numBits . byteAt numBytes
  where
    byteAt i' = BS.head . BS.drop i'
    bitIndex i' = (/= 0) . (.&.) 0x1 . flip shift (i' - 7)
    numBytes = i `div` 8
    numBits  = i `mod` 8

ethChecksum :: EthAddr -> EthAddr
ethChecksum (EthAddr addr) = EthAddr . B8.pack $ go
    (BA.convert . hashWith Keccak_256 $ lower)
    0
    (fmap toLower . B8.unpack $ lower)
  where
    go :: ByteString -> Int -> String -> String
    go _ _ []       = []
    go h i (c : cs) = if bitAt (4 * i) h && not (isDigit c)
        then toUpper c : go h (i + 1) cs
        else c : go h (i + 1) cs
    lower = B8.pack . fmap toLower . B8.unpack $ addr

verifyEthChecksum :: EthAddr -> Bool
verifyEthChecksum = ethChecksum >>= (==)

getLowerEthAddress :: PublicKey -> EthAddr
getLowerEthAddress p =
    EthAddr
        .  B16.encode
        .  BS.drop 12
        .  BA.convert
        .  hashWith Keccak_256
        $  getXCoord p
        <> getYCoord p

isValidEthAddr :: EthAddr -> Bool
isValidEthAddr = is20Chars <&&> isHex <&&> (verifyEthChecksum <||> isLower')
  where
    (<&&>)    = liftA2 (&&)
    (<||>)    = liftA2 (||)
    is20Chars = (== 40) . BS.length . unEthAddr
    isHex     = (== "") . snd . B16.decode . unEthAddr
    isLower'  = all (isLower <||> isDigit) . B8.unpack . unEthAddr


getBtcP2PKHAddress :: NetworkType -> PublicKey -> BtcAddr
getBtcP2PKHAddress t = BtcAddr . base58check v . hash160 . getCompressed
    where v = if t == MainNet then 0x00 else 0x6F

getLtcP2PKHAddress :: NetworkType -> PublicKey -> LtcAddr
getLtcP2PKHAddress t = LtcAddr . base58check v . hash160 . getCompressed
    where v = if t == MainNet then 0x30 else 0x6F

data MultiSigErr = TooManyKeys
                 | MExceedsN
    deriving (Show)

data NetworkType = MainNet
                 | TestNet
    deriving (Eq, Show)

-- will only take up to 15 pub keys,
getBtcMultiSigAddressMain
    :: NetworkType -> [PublicKey] -> Word8 -> Either MultiSigErr BtcAddr
getBtcMultiSigAddressMain t ps m =
    BtcAddr . base58check v . hash160 <$> getBtcMultiSigScript ps m
    where v = if t == MainNet then 0x05 else 0xC4

getLtcMultiSigAddressMain
    :: NetworkType -> [PublicKey] -> Word8 -> Either MultiSigErr LtcAddr
getLtcMultiSigAddressMain t ps m =
    LtcAddr . base58check v . hash160 <$> getBtcMultiSigScript ps m
    where v = if t == MainNet then 0x32 else 0xC4

getBtcMultiSigScript :: [PublicKey] -> Word8 -> Either MultiSigErr ByteString
getBtcMultiSigScript ps m | length ps > 15             = Left TooManyKeys
                          | fromIntegral m > length ps = Left MExceedsN
                          | otherwise                  = Right $ script
  where
    op_m             = encode $ (0x50 + (m .&. 0xF) :: Word8)
    op_n = encode $ (0x50 + (fromIntegral (length ps) .&. 0xF) :: Word8)
    op_checkmultisig = encode (0xAE :: Word8)
    sorted           = sort . fmap getCompressed $ ps
    pubkeyPushes     = mconcat . fmap ("\x4C\x21" <>) $ sorted
    script           = op_m <> pubkeyPushes <> op_n <> op_checkmultisig


base58check :: HashAlgorithm a => Word8 -> Digest a -> ByteString
base58check v d =
    B58.encodeBase58 B58.bitcoinAlphabet $ encode v <> BA.convert d <> checksum
  where
    checksum = BS.take 4 . BA.convert . hash256 $ encode v <> BA.convert d

verifyBtcChecksum :: BtcAddr -> Bool
verifyBtcChecksum addr = case (payload', checksum') of
    (Nothing, _      ) -> False
    (_      , Nothing) -> False
    (Just payload, Just checksum) ->
        BS.take 4 (BA.convert . hash256 $ payload) == checksum
  where
    b58decode = fmap leftpad . B58.decodeBase58 B58.bitcoinAlphabet
    leftpad bs = BS.replicate (25 - BS.length bs) 0 <> bs
    decoded   = b58decode $ unBtcAddr addr
    payload'  = BS.take 21 <$> decoded
    checksum' = BS.drop 21 <$> decoded

verifyLtcChecksum :: LtcAddr -> Bool
verifyLtcChecksum addr = case (payload', checksum') of
    (Nothing, _      ) -> False
    (_      , Nothing) -> False
    (Just payload, Just checksum) ->
        BS.take 4 (BA.convert . hash256 $ payload) == checksum
  where
    b58decode = fmap leftpad . B58.decodeBase58 B58.bitcoinAlphabet
    leftpad bs = BS.replicate (25 - BS.length bs) 0 <> bs
    decoded   = b58decode $ unLtcAddr addr
    payload'  = BS.take 21 <$> decoded
    checksum' = BS.drop 21 <$> decoded

verifyDogeChecksum :: DogeAddr -> Bool
verifyDogeChecksum addr = case (payload', checksum') of
    (Nothing, _      ) -> False
    (_      , Nothing) -> False
    (Just payload, Just checksum) ->
        BS.take 4 (BA.convert . hash256 $ payload) == checksum
  where
    b58decode = fmap leftpad . B58.decodeBase58 B58.bitcoinAlphabet
    leftpad bs = BS.replicate (25 - BS.length bs) 0 <> bs
    decoded   = b58decode $ unDogeAddr addr
    payload'  = BS.take 21 <$> decoded
    checksum' = BS.drop 21 <$> decoded

verifyDashChecksum :: DashAddr -> Bool
verifyDashChecksum addr = case (payload', checksum') of
    (Nothing, _      ) -> False
    (_      , Nothing) -> False
    (Just payload, Just checksum) ->
        BS.take 4 (BA.convert . hash256 $ payload) == checksum
  where
    b58decode = fmap leftpad . B58.decodeBase58 B58.bitcoinAlphabet
    leftpad bs = BS.replicate (25 - BS.length bs) 0 <> bs
    decoded   = b58decode $ unDashAddr addr
    payload'  = BS.take 21 <$> decoded
    checksum' = BS.drop 21 <$> decoded

isValidBtcAddr :: BtcAddr -> Bool
isValidBtcAddr =
    lengthInBounds <&&> isBase58 <&&> verifyBtcChecksum <&&> validVersionByte
  where
    (<&&>)         = liftA2 (&&)
    lengthInBounds = ((>= 26) <&&> (<= 35)) . BS.length . unBtcAddr
    isB58Char      = flip elem . B8.unpack $ B58.unAlphabet B58.bitcoinAlphabet
    isBase58       = all isB58Char . B8.unpack . unBtcAddr
    validVersionByte =
        flip elem ("132mn" :: String) . head . B8.unpack . unBtcAddr


isValidLtcAddr :: LtcAddr -> Bool
isValidLtcAddr =
    lengthInBounds <&&> isBase58 <&&> verifyLtcChecksum <&&> validVersionByte
  where
    (<&&>)         = liftA2 (&&)
    lengthInBounds = ((>= 26) <&&> (<= 35)) . BS.length . unLtcAddr
    isB58Char      = flip elem . B8.unpack $ B58.unAlphabet B58.bitcoinAlphabet
    isBase58       = all isB58Char . B8.unpack . unLtcAddr
    validVersionByte =
        flip elem ("LM2mn" :: String) . head . B8.unpack . unLtcAddr

isValidDogeAddr :: DogeAddr -> Bool
isValidDogeAddr =
    lengthInBounds <&&> isBase58 <&&> verifyDogeChecksum <&&> validVersionByte
  where
    (<&&>)         = liftA2 (&&)
    lengthInBounds = ((>= 26) <&&> (<= 35)) . BS.length . unDogeAddr
    isB58Char      = flip elem . B8.unpack $ B58.unAlphabet B58.bitcoinAlphabet
    isBase58       = all isB58Char . B8.unpack . unDogeAddr
    validVersionByte =
        flip elem ("D9A2mn" :: String) . head . B8.unpack . unDogeAddr

isValidDashAddr :: DashAddr -> Bool
isValidDashAddr =
    lengthInBounds <&&> isBase58 <&&> verifyDashChecksum <&&> validVersionByte
  where
    (<&&>)         = liftA2 (&&)
    lengthInBounds = ((>= 26) <&&> (<= 35)) . BS.length . unDashAddr
    isB58Char      = flip elem . B8.unpack $ B58.unAlphabet B58.bitcoinAlphabet
    isBase58       = all isB58Char . B8.unpack . unDashAddr
    validVersionByte =
        flip elem ("Xy789" :: String) . head . B8.unpack . unDashAddr

ltcConvertTo3Address :: LtcAddr -> Maybe LtcAddr
ltcConvertTo3Address addr = do
    bs         <- B58.decodeBase58 B58.bitcoinAlphabet $ unLtcAddr addr
    scriptHash <- if BS.head bs == 0x32
        then return . BS.take 20 . BS.drop 1 $ bs
        else Nothing
    let payload  = encode (0x05 :: Word8) <> scriptHash
    let checksum = BS.take 4 . BA.convert . hash256 $ payload
    return
        $  LtcAddr
        .  B58.encodeBase58 B58.bitcoinAlphabet
        $  payload
        <> checksum
