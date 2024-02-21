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


test_roundtrips =
  testGroup "Round-trips"
  [ testGroup "Parse the output from display" $
    map testParseDisplayRoundtrip examplePrograms

  , testGroup "Decode the output from encode" $
    map testDecodeEncodeRoundtrip examplePrograms

  ]
  where
    testParseDisplayRoundtrip (title, p) =
      testCase title $
         parse (T.unpack $ displayProgram p)
         @?=
         Right p

    testDecodeEncodeRoundtrip (title, p) =
      testCase title $
         D.decodeProgram (BL.fromStrict $ E.encodeProgram p)
         @?=
         Right p


examplePrograms =
  [ ("store and load a byte",
     [ Store B8 (Reg 1) (Just 2) (Imm 42)
     , Load B8 (Reg 0) (Reg 1) (Just 2)
     , Exit])

  , ("store and load a double word (64-bit)",
     [ Store B64 (Reg 1) Nothing (Imm 42)
     , Binary B64 Add (Reg 1) (Imm 8)
     , Load B64 (Reg 0) (Reg 1) (Just (-8))
     , Exit])

  , ("sum of the first five integers",
     [ Binary B64 Mov (Reg 0) (Imm 0)
     , Binary B32 Mov (Reg 1) (Imm 5)
     , Jmp 2
     , Binary B64 Add (Reg 0) (R (Reg 1))
     , Binary B32 Sub (Reg 1) (Imm 1)
     , JCond Jgt (Reg 1) (Imm 0) (-3)
     , Exit])

  , ("absolute load",
     [ Binary B64 Mov (Reg 6) (R (Reg 1))
     , LoadAbs B32 0
     , Exit])

  , ("indirect load",
     [ Binary B64 Mov (Reg 6) (R (Reg 1))
     , Binary B64 Mov (Reg 2) (Imm 4)
     , LoadInd B32 (Reg 2) 0
     , Exit])

  ]
