{-# LANGUAGE OverloadedStrings #-}
module Crypto.HDTree.AddressSpec (spec) where

import Test.Hspec
import Crypto.HDTree.Address
import Data.Monoid ((<>))
import Data.ByteString.Char8 (unpack)
import Crypto.Secp256k1
import Data.Maybe
import Data.Either.Combinators
import qualified Data.ByteArray.Encoding as BA

spec :: Spec
spec = do
    describe "ethChecksum cases" $ foldr (*>) (pure ()) $ flip fmap ethChecksummedAddrs (\addr ->
        it (unpack $ unEthAddr addr <> " should be checksummed") $ verifyEthChecksum addr `shouldBe` True)
    describe "btcChecksum cases" $ foldr (*>) (pure ()) $ flip fmap btcChecksummedAddrs (\addr ->
        it (unpack $ unBtcAddr addr <> " should be checksummed") $ verifyBtcChecksum addr `shouldBe` True)
    describe "btcChecksum cases" $ foldr (*>) (pure ()) $ flip fmap ltcChecksummedAddrs (\addr ->
        it (unpack $ unLtcAddr addr <> " should be checksummed") $ verifyLtcChecksum addr `shouldBe` True)
    




ethChecksummedAddrs :: [EthAddr]
ethChecksummedAddrs =
    [ EthAddr "52908400098527886E0F7030069857D2E4169EE7"
    , EthAddr "8617E340B3D01FA5F11F306F4090FD50E238070D"
    , EthAddr "de709f2102306220921060314715629080e2fb77"
    , EthAddr "27b1fdb04752bbc536007a920d24acb045561c26"
    , EthAddr "5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
    , EthAddr "fB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
    , EthAddr "dbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB"
    , EthAddr "D1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"
    ]

btcChecksummedAddrs :: [BtcAddr]
btcChecksummedAddrs =
    [ BtcAddr "1AKqAmstcW93wZQpTGS7nrXJD1d4UzPxEZ"
    , BtcAddr "1PNpn72DK6XLgyrLVyQ6A2qhS5s39nUUH1"
    , BtcAddr "1L9fPME1C1yMhRowVTGqd8rRMwnfY5maYs"
    , BtcAddr "17A16QmavnUfCW11DAApiJxp7ARnxN5pGX"
    , BtcAddr "1FjAx6eywbZd5g3i1UeGtvddVyQrf781Nu"
    , BtcAddr "15oLkM3QTji6wc4YXmBZAcy6LKww4woZVd"
    , BtcAddr "19JuQ7BnvDsQmqXxUa45THciHJErsmKNCy"
    , BtcAddr "1B3ySSjxBfv4U2THAxUwN9b3XXB99zZKPN"
    ]

ltcChecksummedAddrs :: [LtcAddr]
ltcChecksummedAddrs =
    [ LtcAddr "MV5rN5EcX1imDS2gEh5jPJXeiW5QN8YrK3"
    ]