module Ebpf.Decode where

import Ebpf.Asm
import qualified Ebpf.Encode as E
import qualified Ebpf.Helpers as H

import qualified Data.ByteString.Lazy as BL
import qualified Data.Binary.Get as BG
import Data.Bits ((.|.),(.&.), shiftL, shiftR, rotateL, rotateR)

instr :: BG.Get Instruction
instr = do
  opc <- BG.getWord8
  dstSrc <- BG.getWord8
  let dst = Reg . fromIntegral $ dstSrc .&. 0x0f
  let src = Reg . fromIntegral $ dstSrc `shiftR` 4
  off <- fromIntegral <$> BG.getWord16le
  imm <- fromIntegral <$> BG.getWord32le
  case opc of
    _ | opc == E.c_EXIT -> return H.exit
    _ | opc == E.c_CALL -> return $ H.call imm
    _ | opc == E.c_ADD32_IMM -> return $ H.add32_i dst imm
    _ | opc == E.c_ADD32_REG -> return $ H.add32_r dst src
    _ | opc == E.c_SUB32_IMM -> return $ H.sub32_i dst imm
    _ | opc == E.c_SUB32_REG -> return $ H.sub32_r dst src
    _ | opc == E.c_MUL32_IMM -> return $ H.mul32_i dst imm
    _ | opc == E.c_MUL32_REG -> return $ H.mul32_r dst src
    _ | opc == E.c_DIV32_IMM -> return $ H.div32_i dst imm
    _ | opc == E.c_DIV32_REG -> return $ H.div32_r dst src
    _ | opc == E.c_OR32_IMM -> return $ H.or32_i dst imm
    _ | opc == E.c_OR32_REG -> return $ H.or32_r dst src
    _ | opc == E.c_AND32_IMM -> return $ H.and32_i dst imm
    _ | opc == E.c_AND32_REG -> return $ H.and32_r dst src
    _ | opc == E.c_LSH32_IMM -> return $ H.lsh32_i dst imm
    _ | opc == E.c_LSH32_REG -> return $ H.lsh32_r dst src
    _ | opc == E.c_RSH32_IMM -> return $ H.rsh32_i dst imm
    _ | opc == E.c_RSH32_REG -> return $ H.rsh32_r dst src
    _ | opc == E.c_NEG32 -> return $ H.neg32 dst
    _ | opc == E.c_MOD32_IMM -> return $ H.mod32_i dst imm
    _ | opc == E.c_MOD32_REG -> return $ H.mod32_r dst src
    _ | opc == E.c_XOR32_IMM -> return $ H.xor32_i dst imm
    _ | opc == E.c_XOR32_REG -> return $ H.xor32_r dst src
    _ | opc == E.c_MOV32_IMM -> return $ H.mov32_i dst imm
    _ | opc == E.c_MOV32_REG -> return $ H.mov32_r dst src
    _ | opc == E.c_ARSH32_IMM -> return $ H.arsh32_i dst imm
    _ | opc == E.c_ARSH32_REG -> return $ H.arsh32_r dst src
    _ | opc == E.c_LE -> return $ H.le32 dst
    _ | opc == E.c_BE -> return $ H.be32 dst
    _ | opc == E.c_ADD64_IMM -> return $ H.add64_i dst imm
    _ | opc == E.c_ADD64_REG -> return $ H.add64_r dst src
    _ | opc == E.c_SUB64_IMM -> return $ H.sub64_i dst imm
    _ | opc == E.c_SUB64_REG -> return $ H.sub64_r dst src
    _ | opc == E.c_MUL64_IMM -> return $ H.mul64_i dst imm
    _ | opc == E.c_MUL64_REG -> return $ H.mul64_r dst src
    _ | opc == E.c_DIV64_IMM -> return $ H.div64_i dst imm
    _ | opc == E.c_DIV64_REG -> return $ H.div64_r dst src
    _ | opc == E.c_OR64_IMM -> return $ H.or64_i dst imm
    _ | opc == E.c_OR64_REG -> return $ H.or64_r dst src
    _ | opc == E.c_AND64_IMM -> return $ H.and64_i dst imm
    _ | opc == E.c_AND64_REG -> return $ H.and64_r dst src
    _ | opc == E.c_LSH64_IMM -> return $ H.lsh64_i dst imm
    _ | opc == E.c_LSH64_REG -> return $ H.lsh64_r dst src
    _ | opc == E.c_RSH64_IMM -> return $ H.rsh64_i dst imm
    _ | opc == E.c_RSH64_REG -> return $ H.rsh64_r dst src
    _ | opc == E.c_NEG64 -> return $ H.neg64 dst
    _ | opc == E.c_MOD64_IMM -> return $ H.mod64_i dst imm
    _ | opc == E.c_MOD64_REG -> return $ H.mod64_r dst src
    _ | opc == E.c_XOR64_IMM -> return $ H.xor64_i dst imm
    _ | opc == E.c_XOR64_REG -> return $ H.xor64_r dst src
    _ | opc == E.c_MOV64_IMM -> return $ H.mov64_i dst imm
    _ | opc == E.c_MOV64_REG -> return $ H.mov64_r dst src
    _ | opc == E.c_ARSH64_IMM -> return $ H.arsh64_i dst imm
    _ | opc == E.c_ARSH64_REG -> return $ H.arsh64_r dst src
    _ | opc == E.c_JA -> return $ H.jmp off
    _ | opc == E.c_JEQ_IMM -> return $ H.jeq_i dst imm off
    _ | opc == E.c_JEQ_REG -> return $ H.jeq_r dst src off
    _ | opc == E.c_JGT_IMM -> return $ H.jgt_i dst imm off
    _ | opc == E.c_JGT_REG -> return $ H.jgt_r dst src off
    _ | opc == E.c_JGE_IMM -> return $ H.jge_i dst imm off
    _ | opc == E.c_JGE_REG -> return $ H.jge_r dst src off
    _ | opc == E.c_JLT_IMM -> return $ H.jlt_i dst imm off
    _ | opc == E.c_JLT_REG -> return $ H.jlt_r dst src off
    _ | opc == E.c_JLE_IMM -> return $ H.jle_i dst imm off
    _ | opc == E.c_JLE_REG -> return $ H.jle_r dst src off
    _ | opc == E.c_JSET_IMM -> return $ H.jset_i dst imm off
    _ | opc == E.c_JSET_REG -> return $ H.jset_r dst src off
    _ | opc == E.c_JNE_IMM -> return $ H.jne_i dst imm off
    _ | opc == E.c_JNE_REG -> return $ H.jne_r dst src off
    _ | opc == E.c_JSGT_IMM -> return $ H.jsgt_i dst imm off
    _ | opc == E.c_JSGT_REG -> return $ H.jsgt_r dst src off
    _ | opc == E.c_JSGE_IMM -> return $ H.jsge_i dst imm off
    _ | opc == E.c_JSGE_REG -> return $ H.jsge_r dst src off
    _ | opc == E.c_JSLT_IMM -> return $ H.jslt_i dst imm off
    _ | opc == E.c_JSLT_REG -> return $ H.jslt_r dst src off
    _ | opc == E.c_JSLE_IMM -> return $ H.jsle_i dst imm off
    _ | opc == E.c_JSLE_REG -> return $ H.jsle_r dst src off
    _ | opc == E.c_LD_B_REG -> return $ H.ldxb dst src off
    _ | opc == E.c_LD_H_REG -> return $ H.ldxh dst src off
    _ | opc == E.c_LD_W_REG -> return $ H.ldxw dst src off
    _ | opc == E.c_LD_DW_REG -> return $ H.ldxdw dst src off
    _ | opc == E.c_LD_ABS_B -> return $ H.ldabsb $ fromIntegral imm
    _ | opc == E.c_LD_ABS_H -> return $ H.ldabsh $ fromIntegral imm
    _ | opc == E.c_LD_ABS_W -> return $ H.ldabsw $ fromIntegral imm
    _ | opc == E.c_LD_ABS_DW -> return $ H.ldabsdw $ fromIntegral imm
    _ | opc == E.c_LD_IND_B -> return $ H.ldindb src $ fromIntegral imm
    _ | opc == E.c_LD_IND_H -> return $ H.ldindh src $ fromIntegral imm
    _ | opc == E.c_LD_IND_W -> return $ H.ldindw src $ fromIntegral imm
    _ | opc == E.c_LD_IND_DW -> return $ H.ldinddw src $ fromIntegral imm
    _ | opc == E.c_ST_B_IMM -> return $ H.stb dst off imm
    _ | opc == E.c_ST_H_IMM -> return $ H.sth dst off imm
    _ | opc == E.c_ST_W_IMM -> return $ H.stw dst off imm
    _ | opc == E.c_ST_DW_IMM -> return $ H.stdw dst off imm
    _ | opc == E.c_ST_B_REG -> return $ H.stxb dst off src
    _ | opc == E.c_ST_H_REG -> return $ H.stxh dst off src
    _ | opc == E.c_ST_W_REG -> return $ H.stxw dst off src
    _ | opc == E.c_ST_DW_REG -> return $ H.stxdw dst off src
    _ | opc == E.c_LD_DW_IMM -> do
          _padding <- BG.getWord32le
          imm64Upper <- fromIntegral <$> BG.getWord32le
          let imm64Lower = fromIntegral imm
          return $ H.lddw dst (imm64Lower + imm64Upper `shiftL` 32)


program :: BG.Get Program
program = do
  done <- BG.isEmpty
  if done
    then return mempty
    else (:) <$> instr <*> program

decodeProgram :: BL.ByteString -> Either String Program
decodeProgram bytes =
  case BG.runGetOrFail program bytes of
    Left (_, _, err) -> Left $ "Could not decode bytes: " ++ err
    Right(_,_, prog) -> Right prog
