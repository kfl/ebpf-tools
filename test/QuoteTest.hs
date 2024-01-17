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
      p [ Binary B64 Mov (Reg 0) (Imm 0)
        , Binary B32 Mov (Reg 1) (Imm 5)
        , Jmp 2
        , Binary B64 Add (Reg 0) (R (Reg 1))
        , Binary B32 Sub (Reg 1) (Imm 1)
        , JCond Jgt (Reg 1) (Imm 0) (-3)
        , Exit]

  , testCase "store and load a byte" $
      [ebpf| stb [r1+2], 0x2a
             ldxb r0, [r1+2]
             exit
             |]
      @?=
      p [ Store B8 (Reg 1) (Just 2) (Imm 42)
        , Load B8 (Reg 0) (Reg 1) (Just 2)
        , Exit]

  , testCase "Splice immediate" $
      let n = Imm 42 in
      [ebpf| stb [r1+2], #{n}
             ldxb r0, [r1+2]
             exit
             |]
      @?=
      p [ Store B8 (Reg 1) (Just 2) n
        , Load B8 (Reg 0) (Reg 1) (Just 2)
        , Exit]

  , testCase "Splice Register" $
      let r = R $ Reg 6 in
      [ebpf| add r1, #{r}
             add r1, r1
             exit
             |]
      @?=
      p [ Binary B64 Add (Reg 1) r
        , Binary B64 Add (Reg 1) (R $ Reg 1)
        , Exit]

      ]

p :: Program -> Program
p = id
