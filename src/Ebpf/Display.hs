{-# LANGUAGE OverloadedStrings #-}
module Ebpf.Display where


import Data.Text.Display
import qualified Data.Char as C
import qualified Data.Text as T

import Ebpf.Asm
import Ebpf.Helpers

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

displayRIBuilder (Left r) = displayBuilder r
displayRIBuilder (Right i) = displayBuilder i

displayRegImm (Left r) = display r
displayRegImm (Right i) = display i

displayMemLocBuilder r moff = mconcat ["[", displayBuilder r, off, "]"]
  where off = case moff of
                Just i | i /= 0 -> " +" <> displayBuilder i
                _ -> ""

instance Display Instruction where
  displayBuilder instr =
    mconcat $
    case instr of
      Binary bsz alu r ir ->
        [displayBuilder alu, displayBuilder bsz, " ", displayBuilder r, ", ", displayRIBuilder ir]
      Unary bsz alu r ->
        [displayBuilder alu, displayBuilder bsz, " ", displayBuilder r]
      Store bsz r moff ir ->
        ["st", x, mem_sz, " ", displayMemLocBuilder r moff, ", ", src]
        where (x, src) = case ir of
                           Left r -> ("x", displayBuilder r)
                           Right i -> ("", displayBuilder i)
              mem_sz = case bsz of B8 -> "b" ; B16 -> "h" ; B32 -> "w" ; B64 -> "dw"
      Load bsz dst src moff ->
        ["ldx", case bsz of B8 -> "b" ; B16 -> "h" ; B32 -> "w" ; B64 -> "dw", " ",
         displayBuilder dst, ", ", displayMemLocBuilder src moff]
      LoadImm r c ->
        ["lddw ", displayBuilder r, ", ", displayBuilder c]
      LoadMapFd r c ->
        ["load_map_fd ", displayBuilder r, ", ", displayBuilder c]
      JCond cmp r ir off ->
        [displayBuilder cmp, " ", displayBuilder r, ", ", displayRIBuilder ir,
         ", +", displayBuilder off]
      Jmp off -> ["ja +", displayBuilder off]
      Call f -> ["call ", displayBuilder f]
      Exit -> ["exit"]
