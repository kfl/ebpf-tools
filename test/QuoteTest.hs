{-# LANGUAGE QuasiQuotes #-}
module QuoteTest where

import Test.Tasty
import Test.Tasty.HUnit

import Ebpf.Asm
import Ebpf.Quote


test_basic :: TestTree
test_basic =
  testGroup "Quasi-quotation test"
  [ testCase "sum of the first five integers" $
      [ebpf|
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
      [ Binary B64 Mov (Reg 0) (Right 0)
      , Binary B32 Mov (Reg 1) (Right 5)
      , Jmp 2
      , Binary B64 Add (Reg 0) (Left (Reg 1))
      , Binary B32 Sub (Reg 1) (Right 1)
      , JCond Jgt (Reg 1) (Right 0) (-3)
      , Exit]

  , testCase "store and load a byte" $
      [ebpf| stb [r1+2], 0x2a
             ldxb r0, [r1+2]
             exit
             |]
      @?=
      [ Store B8 (Reg 1) (Just 2) (Right 42)
      , Load B8 (Reg 0) (Reg 1) (Just 2)
      , Exit]
  ]
