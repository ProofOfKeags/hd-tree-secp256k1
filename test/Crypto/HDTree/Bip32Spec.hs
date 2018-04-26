{-# LANGUAGE OverloadedStrings #-}
module Crypto.HDTree.Bip32Spec (spec) where

import qualified Data.ByteString as BS

import Test.Hspec
import Test.QuickCheck
import Crypto.HDTree.Bip32
import qualified Data.ByteString.Base16 as B16

spec :: Spec
spec = do
    describe "ckdPriv" $ return ()
    describe "ckdPub" $ return ()
    describe "ckdDiagStandard" $ return ()
    describe "ckdDiagHardened" $ return ()
    describe "neuter" $ return ()
    describe "test vector 1" $ do
        let seed = Seed . fst $ B16.decode "000102030405060708090a0b0c0d0e0f"
        describe "m" $ do
            it "priv" $ do
                fmap toAddress (deriveRootPriv seed) `shouldBe` Just "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
            it "pub" $ do
                fmap toAddress (deriveRootPub seed) `shouldBe` Just "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
        describe "m/0'" $ do
            let xpriv = do
                    path <- parsePath "m/0'"
                    root <- deriveRootPriv seed
                    derivePathPriv root path
                xpub = neuter <$> xpriv
            it "priv" $ do
                toAddress <$> xpriv `shouldBe` Just "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
            it "pub" $ do
                toAddress <$> xpub `shouldBe` Just "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"

    describe "test vector 2" $ do
        let seed = Seed . fst $ B16.decode "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
        describe "m" $ do
            it "priv" $ do
                fmap toAddress (deriveRootPriv seed) `shouldBe` Just "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U"
            it "pub" $ do
                fmap toAddress (deriveRootPub seed) `shouldBe` Just "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"
        describe "m/0" $ do
            it "pub" $ do
                let addr = do
                        path <- parsePath "M/0"
                        root <- deriveRootPub seed
                        fmap toAddress (derivePathPub root path)
                addr `shouldBe` Just "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"
            it "priv" $ do
                let addr = do
                        path <- parsePath "m/0"
                        root <- deriveRootPriv seed
                        fmap toAddress (derivePathPriv root (Path True [Index 0]))
                addr `shouldBe` Just "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt"

    describe "test vector 3" $ do
        let seed = Seed . fst $ B16.decode "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be"
        describe "m" $ do
            it "priv" $ do
                fmap toAddress (deriveRootPriv seed) `shouldBe` Just "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6"
            it "pub" $ do
                fmap toAddress (deriveRootPub seed) `shouldBe` Just "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13"

type TestVector = (BS.ByteString, [String, (BS.ByteString, BS.ByteString)])
testVectors :: [TestVector]
test :: TestVector -> Spec
