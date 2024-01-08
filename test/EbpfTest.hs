{- This module in for cross-cutting tests between multiple modules. -}
module EbpfTest where

import Test.Tasty
import Test.Tasty.HUnit

import Ebpf.Asm
import Ebpf.AsmParser
import Ebpf.Display
import Data.Text.Display
import qualified Data.Text as T


test_parse_display =
    testGroup "Parsing the output from display"
    [ testRoundtrip "store and load a byte" $
        [ Store B8 (Reg 1) (Just 2) (Right 42)
        , Load B8 (Reg 0) (Reg 1) (Just 2)
        , Exit]

    , testRoundtrip "store and load a double word (64-bit)" $
        [ Store B64 (Reg 1) Nothing (Right 42)
        , Binary B64 Add (Reg 1) (Right 8)
        , Load B64 (Reg 0) (Reg 1) (Just (-8))
        , Exit]
    ]

testRoundtrip title p =
  testCase title $
      parse (T.unpack $ displayProgram p)
      @?=
      Right p
