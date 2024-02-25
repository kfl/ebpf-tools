{-# LANGUAGE QuasiQuotes #-}
module QuoteTest where

import Test.Tasty
import Test.Tasty.HUnit

import Ebpf.Asm
import Ebpf.Quote
import qualified Ebpf.AsmParser as Parser


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

  , testCase "Splice immediate in reg/imm position" $
      let n = Imm 42 in
      [ebpf| stb [r1+2], $n
             ldxb r0, [r1+2]
             exit
             |]
      @?=
      p [ Store B8 (Reg 1) (Just 2) n
        , Load B8 (Reg 0) (Reg 1) (Just 2)
        , Exit]

  , testCase "Splice register in reg/imm position" $
      let r = R $ Reg 6 in
      [ebpf| add r1, $r
             add r1, r1
             exit
             |]
      @?=
      p [ Binary B64 Add (Reg 1) r
        , Binary B64 Add (Reg 1) (R $ Reg 1)
        , Exit]

  , testCase "Splice immediate in lddw instruction" $
      let n = 424242424242424242 in
      [ebpf| lddw r0, $n
             exit
             |]
      @?=
      p [ LoadImm (Reg 0) n
        , Exit]

  , testCase "Splice register in both reg and reg/imm positions" $
      let r6 = R $ Reg 6
          r1 = Reg 1
          rr1 = R $ Reg 1
      in
      [ebpf| add $r1, $r6
             add r1, $rr1
             exit
             |]
      @?=
      p [ Binary B64 Add r1 r6
        , Binary B64 Add (Reg 1) rr1
        , Exit]

  , testCase "Splice immediate and registers in both reg and reg/imm positions" $
      let n = 0
          r6 = R $ Reg 6
          r1 = Reg 1
          rr1 = R $ Reg 1
      in
      [ebpf| lddw $r1, $n
             add $r1, $r6
             add r1, $rr1
             exit
             |]
      @?=
      p [ LoadImm r1 n
        , Binary B64 Add r1 r6
        , Binary B64 Add (Reg 1) rr1
        , Exit]

  , testCase "Splice immediate in stxb instruction (is arguable wrong)" $
      let n = Imm 42 in
      [ebpf| stxb [r1+2], $n
             exit
             |]
      @?=
      p [ Store B8 (Reg 1) (Just 2) n
        , Exit]

  , testCase "Splice reg in memory reference" $
      let r = Reg 1 in
      [ebpf| stxb [$r + 2], r0
             exit
             |]
      @?=
      p [ Store B8 r (Just 2) (R $ Reg 0)
        , Exit]

  , testCase "Parsing of reasonable splice variables" $
     parseWithSpliceVars Parser.program "mov $r', $a_38"
     @?=
     Right [Binary B64 Mov (Var "r'") (Var "a_38")]

  , testCase "Splice some reasonable variable names" $
      let r' = Reg 1
          a_38 = Reg 0
      in
      [ebpf| mov $r', 0
             mov $a_38, 42
             exit
             |]
      @?=
      p [ Binary B64 Mov r' (Imm 0)
        , Binary B64 Mov a_38 (Imm 42)
        , Exit]

  , testCase "Splice in some map fd" $
      let map_fd = 2 in
        [ebpf| lmfd r1, $map_fd |]
      @?=
      p [ LoadMapFd (Reg 1) map_fd ]

  , testCase "Splice in value in ldabs" $
      let val = 42 in
        [ebpf| ldabsw $val |]
      @?=
      p [ LoadAbs B32 val ]

  , testCase "Splice in function in call" $
      let v_BPF_MAP_LOOKUP_ELEM = 0 in
        [ebpf| call $v_BPF_MAP_LOOKUP_ELEM
               exit |]
      @?=
      p [ Call v_BPF_MAP_LOOKUP_ELEM
        , Exit ]

  , testCase "Splice without spaces" $
      let r = Reg 1 in
      [ebpf| stxb [$r+2], r0
             exit
             |]
      @?=
      p [ Store B8 r (Just 2) (R $ Reg 0)
        , Exit]

      ]


-- A hack to resolve the type of all the (integer) literals
p :: Program -> Program
p = id
