{-# LANGUAGE RecordWildCards #-}
module Crypto.HDTree.Bip32.DerivationPath
    ( parsePath
    , increment
    , Index(..)
    , Path(..)
    ) where

import Control.Applicative ((<|>))
import Data.Word (Word32)
import Text.Trifecta

newtype Index = Index { getIndex :: Word32 } deriving (Eq)
instance Show Index where
    show (Index i) =
        if i >= 0x80000000
            then show (i - 0x80000000) ++ "'"
            else show i

increment :: Index -> Index
increment (Index i)
    | i < 0x80000000 && i + 1 == 0x80000000 = Index 0
    | i >= 0x80000000 && i + 1 == 0 = Index 0x80000000
    | otherwise = Index $ i + 1

newtype Path = Path { privPath :: [Index] } deriving (Eq)
instance Show Path where
    show = ('m':) . ((('/':) . show) =<<) . privPath

parsePath :: String -> Maybe Path
parsePath s = case parseString path mempty s of
    Success a -> Just a
    _ -> Nothing

path :: Parser Path
path = do
    _ <- char 'm'
    privPath <- indexList
    return Path{..}

indexList :: Parser [Index]
indexList = do
    const [] <$> eof <|> do
        _ <- char '/'
        (Index idx) <- index
        offset <- option 0 $ const 0x80000000 <$> char '\''
        rest <- indexList
        return $ (Index $ idx + offset):rest

index :: Parser Index
index = Index . fromIntegral <$> decimal
