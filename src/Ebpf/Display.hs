{-# LANGUAGE OverloadedStrings #-}
module Ebpf.Display where


import Data.Text.Display
import qualified Data.Char as C
import qualified Data.Text as T

import Ebpf.Asm

instance Display Reg where
  displayBuilder (Reg i) = "r" <> displayBuilder i

lowercase opr = map C.toLower $ show opr

instance Display BinAlu where
  displayBuilder alu = displayBuilder $ lowercase alu

instance Display UnAlu where
  displayBuilder alu = displayBuilder $ lowercase alu

instance Display BSize where
  displayBuilder bsz =
    displayBuilder (case bsz of B8 -> T.pack "8" ; B16 -> "16" ; B32 -> "32" ; B64 -> "64")

instance Display Jcmp where
  displayBuilder cmp = displayBuilder $ lowercase cmp

displayRegImm (Left r) = displayBuilder r
displayRegImm (Right i) = displayBuilder i

instance Display Instruction where
  displayBuilder instr =
    mconcat $
    case instr of
      Binary bsz alu r ir ->
        [displayBuilder alu, displayBuilder bsz, " ", displayBuilder r, ", ", displayRegImm ir]
      Unary bsz alu r ->
        [displayBuilder alu, displayBuilder bsz, " ", displayBuilder r]
      Store bsz r moff ir ->
        ["st", x, mem_sz, displayBuilder r, off, " ", src]
        where (x, src) = case ir of
                           Left r -> ("x", displayBuilder r)
                           Right i -> ("", displayBuilder i)
              mem_sz = case bsz of B8 -> "b" ; B16 -> "h" ; B32 -> "w" ; B64 -> "dw"
              off = maybe "" (\ i -> " +"<>displayBuilder i) moff
      Load bsz dst src moff ->
        ["ldx", case bsz of B8 -> "b" ; B16 -> "h" ; B32 -> "w" ; B64 -> "dw", " ",
         displayBuilder dst, ", ",
         displayBuilder src, maybe "" (\ i -> " +"<>displayBuilder i) moff]
      LoadImm r c ->
        ["lddw ", displayBuilder r, ", ", displayBuilder c]
      LoadMapFd r c ->
        ["load_map_fd ", displayBuilder r, ", ", displayBuilder c]
      JCond cmp r ir off ->
        [displayBuilder cmp, " ", displayBuilder r, ", ", displayRegImm ir,
         ", +", displayBuilder off]
      Jmp off -> ["ja +", displayBuilder off]
      Call f -> ["call ", displayBuilder f]
      Exit -> ["exit"]
