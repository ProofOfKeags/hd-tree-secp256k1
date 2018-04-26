module Crypto.HDTree.Constants
    ( xprivMagicMain
    , xpubMagicMain
    , xprivMagicTest
    , xpubMagicTest
    ) where

import Data.Word

xpubMagicMain :: Word32
xpubMagicMain = 0x0488B21E

xpubMagicTest :: Word32
xpubMagicTest = 0x043587CF

xprivMagicMain :: Word32
xprivMagicMain = 0x0488ADE4

xprivMagicTest :: Word32
xprivMagicTest = 0x04358394