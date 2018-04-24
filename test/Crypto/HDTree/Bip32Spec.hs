module Crypto.HDTree.Bip32Spec (spec) where

import qualified Data.ByteString as BS

import Test.Hspec
import Test.QuickCheck
import Crypto.HDTree.Bip32

spec :: Spec
spec = do
    describe "ckdPriv" $ return ()
    describe "ckdPub" $ return ()
    describe "ckdDiagStandard" $ return ()
    describe "ckdDiagHardened" $ return ()
    describe "neuter" $ return ()
    describe "test vector 1" $ do
        describe "m" $ do
            it "pub" $ do
                toAddress (derivePathPub "m") `shouldBe` "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"