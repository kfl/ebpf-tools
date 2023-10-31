module Ebpf.Decode where

import Ebpf.Asm
import qualified Ebpf.Encode as E
import qualified Ebpf.Helpers as H


import qualified Data.ByteString as B
import qualified Data.Binary.Get as BG
import Data.Bits ((.|.),(.&.), shiftL, shiftR, rotateL, rotateR)


instr :: BG.Get Instruction
instr = do
  opc <- BG.getWord8
  dstSrc <- BG.getWord8
  let dst = Reg . fromIntegral $ dstSrc .&. 0x0f
  let src = Reg . fromIntegral $ dstSrc `shiftR` 4
  off <- fromIntegral <$> BG.getWord16le
  imm <- BG.getWord32le
  return $
    case opc of
      _ | opc == E.c_EXIT -> Exit
      _ | opc == E.c_CALL -> Call $ fromIntegral imm
      _ | opc == E.c_ADD32_IMM -> H.add32_i dst $ fromIntegral imm
      _ | opc == E.c_ADD32_REG -> H.add32_r dst src
      _ | opc == E.c_SUB32_IMM -> H.sub32_i dst $ fromIntegral imm
      _ | opc == E.c_SUB32_REG -> H.sub32_r dst src
      _ | opc == E.c_MUL32_IMM -> H.mul32_i dst $ fromIntegral imm
      _ | opc == E.c_MUL32_REG -> H.mul32_r dst src
      _ | opc == E.c_DIV32_IMM -> H.div32_i dst $ fromIntegral imm
      _ | opc == E.c_DIV32_REG -> H.div32_r dst src
      _ | opc == E.c_OR32_IMM -> H.or32_i dst $ fromIntegral imm
      _ | opc == E.c_OR32_REG -> H.or32_r dst src
      _ | opc == E.c_AND32_IMM -> H.and32_i dst $ fromIntegral imm
      _ | opc == E.c_AND32_REG -> H.and32_r dst src
      _ | opc == E.c_LSH32_IMM -> H.lsh32_i dst $ fromIntegral imm
      _ | opc == E.c_LSH32_REG -> H.lsh32_r dst src
      _ | opc == E.c_RSH32_IMM -> H.rsh32_i dst $ fromIntegral imm
      _ | opc == E.c_RSH32_REG -> H.rsh32_r dst src
      _ | opc == E.c_NEG32 -> H.neg32 dst
      _ | opc == E.c_MOD32_IMM -> H.mod32_i dst $ fromIntegral imm
      _ | opc == E.c_MOD32_REG -> H.mod32_r dst src
      _ | opc == E.c_XOR32_IMM -> H.xor32_i dst $ fromIntegral imm
      _ | opc == E.c_XOR32_REG -> H.xor32_r dst src
      _ | opc == E.c_MOV32_IMM -> H.mov32_i dst $ fromIntegral imm
      _ | opc == E.c_MOV32_REG -> H.mov32_r dst src
      _ | opc == E.c_ARSH32_IMM -> H.arsh32_i dst $ fromIntegral imm
      _ | opc == E.c_ARSH32_REG -> H.arsh32_r dst src
      _ | opc == E.c_LE -> H.le32 dst
      _ | opc == E.c_BE -> H.be32 dst
      _ | opc == E.c_ADD64_IMM -> H.add64_i dst $ fromIntegral imm
      _ | opc == E.c_ADD64_REG -> H.add64_r dst src
      _ | opc == E.c_SUB64_IMM -> H.sub64_i dst $ fromIntegral imm
      _ | opc == E.c_SUB64_REG -> H.sub64_r dst src
      _ | opc == E.c_MUL64_IMM -> H.mul64_i dst $ fromIntegral imm
      _ | opc == E.c_MUL64_REG -> H.mul64_r dst src
      _ | opc == E.c_DIV64_IMM -> H.div64_i dst $ fromIntegral imm
      _ | opc == E.c_DIV64_REG -> H.div64_r dst src
      _ | opc == E.c_OR64_IMM -> H.or64_i dst $ fromIntegral imm
      _ | opc == E.c_OR64_REG -> H.or64_r dst src
      _ | opc == E.c_AND64_IMM -> H.and64_i dst $ fromIntegral imm
      _ | opc == E.c_AND64_REG -> H.and64_r dst src
      _ | opc == E.c_LSH64_IMM -> H.lsh64_i dst $ fromIntegral imm
      _ | opc == E.c_LSH64_REG -> H.lsh64_r dst src
      _ | opc == E.c_RSH64_IMM -> H.rsh64_i dst $ fromIntegral imm
      _ | opc == E.c_RSH64_REG -> H.rsh64_r dst src
      _ | opc == E.c_NEG64 -> H.neg64 dst
      _ | opc == E.c_MOD64_IMM -> H.mod64_i dst $ fromIntegral imm
      _ | opc == E.c_MOD64_REG -> H.mod64_r dst src
      _ | opc == E.c_XOR64_IMM -> H.xor64_i dst $ fromIntegral imm
      _ | opc == E.c_XOR64_REG -> H.xor64_r dst src
      _ | opc == E.c_MOV64_IMM -> H.mov64_i dst $ fromIntegral imm
      _ | opc == E.c_MOV64_REG -> H.mov64_r dst src
      _ | opc == E.c_ARSH64_IMM -> H.arsh64_i dst $ fromIntegral imm
      _ | opc == E.c_ARSH64_REG -> H.arsh64_r dst src
      _ | opc == E.c_JA -> H.jmp off
      _ | opc == E.c_JEQ_IMM -> H.jeq_i dst (fromIntegral imm) off
      _ | opc == E.c_JEQ_REG -> H.jeq_r dst src off
      _ | opc == E.c_JGT_IMM -> H.jgt_i dst (fromIntegral imm) off
      _ | opc == E.c_JGT_REG -> H.jgt_r dst src off
      _ | opc == E.c_JGE_IMM -> H.jge_i dst (fromIntegral imm) off
      _ | opc == E.c_JGE_REG -> H.jge_r dst src off
      _ | opc == E.c_JLT_IMM -> H.jlt_i dst (fromIntegral imm) off
      _ | opc == E.c_JLT_REG -> H.jlt_r dst src off
      _ | opc == E.c_JLE_IMM -> H.jle_i dst (fromIntegral imm) off
      _ | opc == E.c_JLE_REG -> H.jle_r dst src off
      _ | opc == E.c_JSET_IMM -> H.jset_i dst (fromIntegral imm) off
      _ | opc == E.c_JSET_REG -> H.jset_r dst src off
      _ | opc == E.c_JNE_IMM -> H.jne_i dst (fromIntegral imm) off
      _ | opc == E.c_JNE_REG -> H.jne_r dst src off
      _ | opc == E.c_JSGT_IMM -> H.jsgt_i dst (fromIntegral imm) off
      _ | opc == E.c_JSGT_REG -> H.jsgt_r dst src off
      _ | opc == E.c_JSGE_IMM -> H.jsge_i dst (fromIntegral imm) off
      _ | opc == E.c_JSGE_REG -> H.jsge_r dst src off
      _ | opc == E.c_JSLT_IMM -> H.jslt_i dst (fromIntegral imm) off
      _ | opc == E.c_JSLT_REG -> H.jslt_r dst src off
      _ | opc == E.c_JSLE_IMM -> H.jsle_i dst (fromIntegral imm) off
      _ | opc == E.c_JSLE_REG -> H.jsle_r dst src off
      _ | opc == E.c_LD_DW_IMM -> H.lddw dst $ fromIntegral imm
      _ | opc == E.c_LD_B_REG -> H.ldxb dst src off
      _ | opc == E.c_LD_H_REG -> H.ldxh dst src off
      _ | opc == E.c_LD_W_REG -> H.ldxw dst src off
      _ | opc == E.c_LD_DW_REG -> H.ldxdw dst src off
      _ | opc == E.c_ST_B_IMM -> H.stb dst off $ fromIntegral imm
      _ | opc == E.c_ST_H_IMM -> H.sth dst off $ fromIntegral imm
      _ | opc == E.c_ST_W_IMM -> H.stw dst off $ fromIntegral imm
      _ | opc == E.c_ST_DW_IMM -> H.stdw dst off $ fromIntegral imm
      _ | opc == E.c_ST_B_REG -> H.stxb dst off src
      _ | opc == E.c_ST_H_REG -> H.stxh dst off src
      _ | opc == E.c_ST_W_REG -> H.stxw dst off src
      _ | opc == E.c_ST_DW_REG -> H.stxdw dst off src




program :: BG.Get Program
program = do
  done <- BG.isEmpty
  if done
    then return mempty
    else (:) <$> instr <*> program
