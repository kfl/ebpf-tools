{-# LANGUAGE FlexibleInstances, LambdaCase, OverloadedStrings #-}
module Ebpf.Display where


import Data.Text.Display
import qualified Data.Text.Lazy.Builder as TB
import qualified Data.Char as C
import qualified Data.Text as T

import Ebpf.Asm

instance Display Reg where
  displayBuilder (Reg i) = "r" <> displayBuilder i

lowercaseShow :: Show a => a -> TB.Builder
lowercaseShow x = displayBuilder $ map C.toLower $ show x

instance Display BinAlu where
  displayBuilder = lowercaseShow

instance Display UnAlu where
  displayBuilder = lowercaseShow

instance Display BSize where
  displayBuilder = TB.fromText . \case B8 -> "8" ; B16 -> "16" ; B32 -> "32" ; B64 -> "64"

instance Display Jcmp where
  displayBuilder = lowercaseShow

instance Display RegImm where
  displayBuilder (R r) = displayBuilder r
  displayBuilder (Imm n) = displayBuilder n

displayMemLocBuilder r moff = mconcat ["[", displayBuilder r, off, "]"]
  where off = case moff of
                Just i | i /= 0 -> " +" <> displayBuilder i
                _ -> ""

memSz = \case B8 -> "b" ; B16 -> "h" ; B32 -> "w" ; B64 -> "dw"

instance Display (Inst Reg Imm RegImm HelperId) where
  displayBuilder instr =
    mconcat $
    case instr of
      Binary bsz alu r ir ->
        [displayBuilder alu, displayBuilder bsz, " ", displayBuilder r, ", ", displayBuilder ir]
      Unary bsz alu r ->
        [displayBuilder alu, displayBuilder bsz, " ", displayBuilder r]
      Store bsz r moff ir ->
        ["st", x, memSz bsz, " ", displayMemLocBuilder r moff, ", ", src]
        where (x, src) = case ir of
                           R r -> ("x", displayBuilder r)
                           Imm i -> ("", displayBuilder i)
      Load bsz dst src moff ->
        ["ldx", memSz bsz, " ", displayBuilder dst, ", ", displayMemLocBuilder src moff]
      LoadImm r c ->
        ["lddw ", displayBuilder r, ", ", displayBuilder c]
      LoadMapFd r c ->
        ["load_map_fd ", displayBuilder r, ", ", displayBuilder c]
      LoadAbs bsz i ->
        ["ldabs", memSz bsz, " ", displayBuilder i]
      LoadInd bsz src i ->
        ["ldind", memSz bsz, " ", displayBuilder src, " ", displayBuilder i]
      JCond cmp r ir off ->
        [displayBuilder cmp, " ", displayBuilder r, ", ", displayBuilder ir,
         ", +", displayBuilder off]
      Jmp off -> ["ja +", displayBuilder off]
      Call f -> ["call ", displayBuilder f]
      Exit -> ["exit"]

displayProgram :: Program -> T.Text
displayProgram prog =
  T.concat $ map (\i -> display i <> "\n") prog
