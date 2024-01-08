{-# LANGUAGE QuasiQuotes #-}
module AsmParserTest where

import Test.Tasty
import Test.Tasty.HUnit

import Text.RawString.QQ

import Ebpf.Asm
import Ebpf.AsmParser


test_basic :: TestTree
test_basic =
  testGroup "Basic parsing tasty"
  [ testCase "add" $
      parse "add r1, 42"
      @?=
      Right [Binary B64 Add (Reg 1) $ Right 42]

  , testCase "add64 instruction" $
      parse "add64 r0, r6"
      @?=
      Right [Binary B64 Add (Reg 0) $ Left $ Reg 6]

  , testCase "add32 instruction" $
      parse "add32 r9 -1"
      @?=
      Right [Binary B32 Add (Reg 9) $ Right (-1)]

  , testCase "sum of the first five integers" $
      parse [r|
;; Compute the sum of the first five integers
    mov r0, 0
    mov32 r1, 5
    ja +2
    add r0, r1
    sub32 r1, 1
    jgt r1, 0, +-3
    exit
      |]
      @?=
      Right [ Binary B64 Mov (Reg 0) (Right 0)
            , Binary B32 Mov (Reg 1) (Right 5)
            , Jmp 2
            , Binary B64 Add (Reg 0) (Left (Reg 1))
            , Binary B32 Sub (Reg 1) (Right 1)
            , JCond Jgt (Reg 1) (Right 0) (-3)
            , Exit]
  ]
