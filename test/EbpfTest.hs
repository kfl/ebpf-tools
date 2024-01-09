{- This module is for cross-cutting tests between multiple modules. -}
module EbpfTest where

import Test.Tasty
import Test.Tasty.HUnit

import Ebpf.Asm
import Ebpf.AsmParser
import Ebpf.Display
import qualified Data.Text as T
import qualified Ebpf.Encode as E
import qualified Ebpf.Decode as D
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL



test_parse_display =
    testGroup "Parse the output from display" $
    map testParseDisplayRoundtrip examplePrograms

testParseDisplayRoundtrip (title, p) =
  testCase title $
      parse (T.unpack $ displayProgram p)
      @?=
      Right p


test_decode_encode =
    testGroup "Decode the output from encode" $
    map testDecodeEncodeRoundtrip examplePrograms

testDecodeEncodeRoundtrip (title, p) =
  testCase title $
      D.decodeProgram (BL.fromStrict $ E.encodeProgram p)
      @?=
      Right p


examplePrograms =
  [ ("store and load a byte",
     [ Store B8 (Reg 1) (Just 2) (Right 42)
     , Load B8 (Reg 0) (Reg 1) (Just 2)
     , Exit])

  , ("store and load a double word (64-bit)",
     [ Store B64 (Reg 1) Nothing (Right 42)
     , Binary B64 Add (Reg 1) (Right 8)
     , Load B64 (Reg 0) (Reg 1) (Just (-8))
     , Exit])

  ]
