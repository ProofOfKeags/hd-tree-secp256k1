{-# LANGUAGE OverloadedStrings #-}
module Crypto.HDTree.Address where

import Crypto.HDTree.Bip32
import Crypto.Hash
import Data.Bits
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Base58 as B58
import qualified Data.ByteArray as BA
import Data.Char
import Data.List
import Data.Monoid
import Data.Serialize
import Data.Word

newtype EthAddr = EthAddr { unEthAddr :: ByteString } deriving (Eq, Show)
newtype BtcAddr = BtcAddr { unBtcAddr :: ByteString } deriving (Eq, Show)

getEthAddress :: PublicKey -> EthAddr
getEthAddress = ethChecksum . getLowerEthAddress

bitAt :: Int -> ByteString -> Bool
bitAt i = bitIndex numBits . byteAt numBytes
    where
        byteAt i' = BS.head . BS.drop i'
        bitIndex i' = (/=0) . (.&.) 0x1 . flip shift (i'-7)
        numBytes = i `div` 8
        numBits = i `mod` 8

ethChecksum :: EthAddr -> EthAddr
ethChecksum (EthAddr addr) = EthAddr . B8.pack $ go (BA.convert . hashWith Keccak_256 $ lower) 0 (fmap toLower . B8.unpack $ lower)
    where
        go :: ByteString -> Int -> String -> String
        go _ _ [] = []
        go h i (c:cs) = if bitAt (4*i) h && not (isDigit c)
            then toUpper c : go h (i+1) cs
            else c : go h (i+1) cs
        lower = B8.pack . fmap toLower . B8.unpack $ addr

verifyEthChecksum :: EthAddr -> Bool
verifyEthChecksum = ethChecksum >>= (==)

getLowerEthAddress :: PublicKey -> EthAddr
getLowerEthAddress p = EthAddr . B16.encode . BS.drop 12 . BA.convert . hashWith Keccak_256 $ getXCoord p <> getYCoord p

getBtcP2PKHAddress :: NetworkType -> PublicKey -> BtcAddr
getBtcP2PKHAddress t p = base58check v . hash160 . getCompressed $ p
    where
        v = if t == MainNet then 0x00 else 0x6F

data MultiSigErr = TooManyKeys
                 | MExceedsN
    deriving (Show)

data NetworkType = MainNet
                 | TestNet
    deriving (Eq)

-- will only take up to 15 pub keys, 
getBtcMultiSigAddressMain :: NetworkType -> [PublicKey] -> Word8 -> Either MultiSigErr BtcAddr
getBtcMultiSigAddressMain t ps m = base58check v . hash160 <$> getBtcMultiSigScript ps m
    where v = if t == MainNet then 0x05 else 0xC4

getBtcMultiSigScript :: [PublicKey] -> Word8 -> Either MultiSigErr ByteString
getBtcMultiSigScript ps m
    | length ps > 15 = Left TooManyKeys
    | fromIntegral m > length ps = Left MExceedsN
    | otherwise = Right $ script
    where
        op_m = encode $ (0x50 + (m .&. 0xF) :: Word8)
        op_n = encode $ (0x50 + (fromIntegral (length ps) .&. 0xF) :: Word8)
        op_checkmultisig = encode (0xAE :: Word8)
        sorted = sort . fmap getCompressed $ ps
        pubkeyPushes = mconcat . fmap ("\x4C\x21" <>) $ sorted
        script = op_m <> pubkeyPushes <> op_n <> op_checkmultisig


base58check :: HashAlgorithm a => Word8 -> Digest a -> BtcAddr
base58check v d = BtcAddr . B58.encodeBase58 B58.bitcoinAlphabet $ encode v <> BA.convert d <> checksum
    where
        checksum = BS.take 4 . BA.convert . hash256 $ encode v <> BA.convert d

verifyBtcChecksum :: BtcAddr -> Bool
verifyBtcChecksum addr =
    case (payload', checksum') of
        (Nothing, _) -> False
        (_, Nothing) -> False
        (Just payload, Just checksum) -> BS.take 4 (BA.convert . hash256 $ payload) == checksum
    where
        b58decode = B58.decodeBase58 B58.bitcoinAlphabet
        decoded = b58decode $ unBtcAddr addr
        payload' = BS.take 21 <$> decoded
        checksum' = BS.drop 21 <$> decoded
