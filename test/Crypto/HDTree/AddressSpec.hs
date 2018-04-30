{-# LANGUAGE OverloadedStrings #-}
module Crypto.HDTree.AddressSpec (spec) where

import Test.Hspec
import Crypto.HDTree.Address

spec :: Spec
spec = do
    describe "ethChecksum" $ do
        it "all caps" $ do
            verifyEthChecksum (EthAddr "52908400098527886E0F7030069857D2E4169EE7") `shouldBe` True
            verifyEthChecksum (EthAddr "8617E340B3D01FA5F11F306F4090FD50E238070D") `shouldBe` True
            verifyEthChecksum (EthAddr "de709f2102306220921060314715629080e2fb77") `shouldBe` True
            verifyEthChecksum (EthAddr "27b1fdb04752bbc536007a920d24acb045561c26") `shouldBe` True
            verifyEthChecksum (EthAddr "5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed") `shouldBe` True
            verifyEthChecksum (EthAddr "fB6916095ca1df60bB79Ce92cE3Ea74c37c5d359") `shouldBe` True
            verifyEthChecksum (EthAddr "dbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB") `shouldBe` True
            verifyEthChecksum (EthAddr "D1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb") `shouldBe` True
