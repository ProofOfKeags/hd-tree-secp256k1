module Crypto.HDTree.Address where

import Crypto.HDTree.Bip32
import Crypto.Hash
import Data.Bits
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteArray as BA
import Data.Char
import Data.Monoid

newtype EthAddr = EthAddr { unEthAddr :: ByteString } deriving (Eq, Show)
newtype BtcAddr = BtcAddr { unBtcAddr :: ByteString }

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