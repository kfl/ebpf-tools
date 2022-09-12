module Ebpf.Decode where

import Ebpf.Asm
import qualified Ebpf.Encode as E

import qualified Data.ByteString as B
import qualified Data.Binary.Get as BG



instr :: BG.Get Instruction
instr = do
  opc <- BG.getWord8
  dst <- BG.getWord8
  src <- BG.getWord8
  off <- BG.getWord16le
  imm <- BG.getWord32le
  return $
    case opc of
      _ | opc == E.c_EXIT -> Exit
      _ | opc == E.c_CALL -> Call (fromIntegral imm)
      _ | opc == E.c_JA -> Jmp (fromIntegral off)
