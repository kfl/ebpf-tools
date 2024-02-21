{-# LANGUAGE NumericUnderscores #-}
{- HLINT ignore "Use camelCase" -}
module Ebpf.Encode where

import Ebpf.Asm
import Data.Word
import Data.Bits ((.|.),(.&.), shiftL, shiftR, rotateL, rotateR)


import qualified Data.ByteString as B

w8 :: Integral n => n -> Word8
w8 = fromIntegral

w16 :: Integral n => n -> Word16
w16 = fromIntegral

w32 :: Integral n => n -> Word32
w32 = fromIntegral


instr :: Word8 -> Word8 -> Word8 -> Word16 -> Word32 -> B.ByteString
instr opc -- Operation code.
      dst -- Destination register operand.
      src -- Source register operand.
      off -- Offset operand.
      imm -- Immediate value operand.
  = B.pack
    [ opc,
      src `shiftL` 4 .|. dst,
      w8 $ off .&. 0xff,
      w8 $ off `rotateR` 8,
      w8 $ imm .&. 0xff,
      w8 $ (imm .&. 0xff_00) `rotateR` 8,
      w8 $ (imm .&. 0xff_00_00) `rotateR` 16,
      w8 $ (imm .&. 0xff_00_00_00) `rotateR` 24
      ]

encBinary bs alu (Reg dst) src = instr (balu .|. bbs .|. bmod) bdst bsrc 0 bimm
  where
    bbs = case bs of
            B32 -> c_BPF_ALU
            B64 -> c_BPF_ALU64
    bdst = w8 dst
    balu = case alu of
             Add -> c_BPF_ADD
             Sub -> c_BPF_SUB
             Mul -> c_BPF_MUL
             Div -> c_BPF_DIV
             Or -> c_BPF_OR
             And -> c_BPF_AND
             Lsh -> c_BPF_LSH
             Rsh -> c_BPF_RSH
             Mod -> c_BPF_MOD
             Xor -> c_BPF_XOR
             Mov -> c_BPF_MOV
             Arsh -> c_BPF_ARSH
    (bmod, bsrc, bimm) = case src of
                           R(Reg src) -> (c_BPF_X, w8 src, 0)
                           Imm imm -> (c_BPF_K, 0, w32 imm)

encUnary bs Neg (Reg dst) = instr (c_BPF_NEG .|. bbs) (w8 dst) 0 0 0
  where
    bbs = case bs of
            B32 -> c_BPF_ALU
            B64 -> c_BPF_ALU64
encUnary bs alu (Reg dst) = instr balu (w8 dst) 0 0 imm
  where
    balu = case alu of
             Le -> c_LE
             Be -> c_BE
    imm = case bs of
            B16 -> 16
            B32 -> 32
            B64 -> 64

encStore bs (Reg dst) off src = instr (c_BPF_MEM .|. bmod .|. bbs) (w8 dst) bsrc boff bimm
  where
    (bmod, bsrc, bimm) = case src of
                           R(Reg src) -> (c_BPF_STX, w8 src, 0)
                           Imm imm -> (c_BPF_ST, 0, w32 imm)
    bbs = case bs of
            B8 -> c_BPF_B
            B16 -> c_BPF_H
            B32 -> c_BPF_W
            B64 -> c_BPF_DW

    boff = maybe 0 w16 off

encLoad bs (Reg dst) (Reg src) off = instr (c_BPF_MEM .|. c_BPF_LDX .|. bbs) (w8 dst) (w8 src) boff 0
  where
    bbs = case bs of
            B8 -> c_BPF_B
            B16 -> c_BPF_H
            B32 -> c_BPF_W
            B64 -> c_BPF_DW
    boff = maybe 0 w16 off

encLabs bs imm = instr (c_BPF_ABS .|. bbs .|. c_BPF_LD) 0 0 0 (w32 imm)
  where
    bbs = case bs of
            B8 -> c_BPF_B
            B16 -> c_BPF_H
            B32 -> c_BPF_W
            B64 -> c_BPF_DW

encLind bs (Reg src) imm = instr (c_BPF_IND .|. bbs .|. c_BPF_LD) 0 (w8 src) 0 (w32 imm)
  where
    bbs = case bs of
            B8 -> c_BPF_B
            B16 -> c_BPF_H
            B32 -> c_BPF_W
            B64 -> c_BPF_DW

encJCond jcmp (Reg dst) src off = instr (c_BPF_JMP .|. bmod .|. bjcmp) (w8 dst) bsrc (w16 off) bimm
  where
    (bmod, bsrc, bimm) = case src of
                           R(Reg src) -> (c_BPF_X, w8 src, 0)
                           Imm imm -> (c_BPF_K, 0, w32 imm)
    bjcmp = case jcmp of
              Jeq -> c_BPF_JEQ
              Jgt -> c_BPF_JGT
              Jge -> c_BPF_JGE
              Jlt -> c_BPF_JLT
              Jle -> c_BPF_JLE
              Jset -> c_BPF_JSET
              Jne -> c_BPF_JNE
              Jsgt -> c_BPF_JSGT
              Jsge -> c_BPF_JSGE
              Jslt -> c_BPF_JSLT
              Jsle -> c_BPF_JSLE

encInstruction :: Instruction -> B.ByteString
encInstruction inst =
  case inst of
    Binary bs alu dst src -> encBinary bs alu dst src
    Unary bs alu dst -> encUnary bs alu dst
    Store bs dst off src -> encStore bs dst off src
    Load bs dst src off -> encLoad bs dst src off
    LoadImm (Reg dst) imm -> instr c_LD_DW_IMM (w8 dst) 0 0 (w32 imm) <>
                             instr 0 0 0 0 (w32 (imm `shiftR` 32))
    LoadMapFd (Reg dst) imm -> instr c_LD_DW_IMM (w8 dst) c_BPF_PSEUDO_MAP_FD 0 (w32 imm) <>
                               instr 0 0 0 0 (w32 (imm `shiftR` 32))
    LoadAbs bs imm -> encLabs bs imm
    LoadInd bs src imm -> encLind bs src imm
    JCond jcmp dst src off -> encJCond jcmp dst src off
    Jmp off -> instr c_JA 0 0 (w16 off) 0
    Call imm -> instr c_CALL 0 0 0 (w32 imm)
    Exit -> instr c_EXIT 0 0 0 0

encodeProgram :: Program -> B.ByteString
encodeProgram instrs = foldMap encInstruction instrs


-- eBPF op codes.  See
-- https://www.kernel.org/doc/html/latest/bpf/instruction-set.html and
-- also https://www.kernel.org/doc/Documentation/networking/filter.txt

-- Three least significant bits are operation class:
--  BPF operation class: non-standard load operations load from immediate.
c_BPF_LD :: Word8
c_BPF_LD = 0x00
--  BPF operation class: load into register.
c_BPF_LDX :: Word8
c_BPF_LDX = 0x01
--  BPF operation class: store immediate.
c_BPF_ST :: Word8
c_BPF_ST = 0x02
--  BPF operation class: store value from register.
c_BPF_STX :: Word8
c_BPF_STX = 0x03
--  BPF operation class: 32 bits arithmetic operation.
c_BPF_ALU :: Word8
c_BPF_ALU = 0x04
--  BPF operation class: jump.
c_BPF_JMP :: Word8
c_BPF_JMP = 0x05
--  BPF operation class: 32-bit jump.
c_BPF_JMP32 :: Word8
c_BPF_JMP32 = 0x06
--  BPF operation class: 64 bits arithmetic operation.
c_BPF_ALU64 :: Word8
c_BPF_ALU64 = 0x07


-- Source modifiers:
--  BPF source operand modifier: 32-bit immediate value.
c_BPF_K :: Word8
c_BPF_K = 0x00
--  BPF source operand modifier: `src` register.
c_BPF_X :: Word8
c_BPF_X = 0x08


-- For load and store instructions:
-- +------------+--------+------------+
-- |   3 bits   | 2 bits |   3 bits   |
-- |    mode    |  size  | insn class |
-- +------------+--------+------------+
-- (MSB)                          (LSB)

-- Size modifiers:
--  BPF size modifier: word (4 bytes).
c_BPF_W :: Word8
c_BPF_W = 0x00
--  BPF size modifier: half-word (2 bytes).
c_BPF_H :: Word8
c_BPF_H = 0x08
--  BPF size modifier: byte (1 byte).
c_BPF_B :: Word8
c_BPF_B = 0x10
--  BPF size modifier: double word (8 bytes).
c_BPF_DW :: Word8
c_BPF_DW = 0x18

-- Mode modifiers:
--  BPF mode modifier: immediate value.
c_BPF_IMM :: Word8
c_BPF_IMM = 0x00
--  BPF mode modifier: absolute load.
c_BPF_ABS :: Word8
c_BPF_ABS = 0x20
--  BPF mode modifier: indirect load.
c_BPF_IND :: Word8
c_BPF_IND = 0x40
--  BPF mode modifier: load from / store to memory.
c_BPF_MEM :: Word8
c_BPF_MEM = 0x60
--  BPF mode modifier: atomic operations
c_BPF_ATOMIC :: Word8
c_BPF_ATOMIC = 0xc0

c_BPF_PSEUDO_MAP_FD :: Word8
c_BPF_PSEUDO_MAP_FD = 1


-- For arithmetic (BPF_ALU/BPF_ALU64) and jump (BPF_JMP) instructions:
-- +----------------+--------+--------+
-- |     4 bits     |1 b.|   3 bits   |
-- | operation code | src| insn class |
-- +----------------+----+------------+
-- (MSB)                          (LSB)


-- Operation codes -- BPF_ALU or BPF_ALU64 classes:
--  BPF ALU/ALU64 operation code: addition.
c_BPF_ADD :: Word8
c_BPF_ADD = 0x00
--  BPF ALU/ALU64 operation code: subtraction.
c_BPF_SUB :: Word8
c_BPF_SUB = 0x10
--  BPF ALU/ALU64 operation code: multiplication.
c_BPF_MUL :: Word8
c_BPF_MUL = 0x20
--  BPF ALU/ALU64 operation code: division.
c_BPF_DIV :: Word8
c_BPF_DIV = 0x30
--  BPF ALU/ALU64 operation code: or.
c_BPF_OR :: Word8
c_BPF_OR = 0x40
--  BPF ALU/ALU64 operation code: and.
c_BPF_AND :: Word8
c_BPF_AND = 0x50
--  BPF ALU/ALU64 operation code: left shift.
c_BPF_LSH :: Word8
c_BPF_LSH = 0x60
--  BPF ALU/ALU64 operation code: right shift.
c_BPF_RSH :: Word8
c_BPF_RSH = 0x70
--  BPF ALU/ALU64 operation code: negation.
c_BPF_NEG :: Word8
c_BPF_NEG = 0x80
--  BPF ALU/ALU64 operation code: modulus.
c_BPF_MOD :: Word8
c_BPF_MOD = 0x90
--  BPF ALU/ALU64 operation code: exclusive or.
c_BPF_XOR :: Word8
c_BPF_XOR = 0xa0
--  BPF ALU/ALU64 operation code: move.
c_BPF_MOV :: Word8
c_BPF_MOV = 0xb0
--  BPF ALU/ALU64 operation code: sign extending right shift.
c_BPF_ARSH :: Word8
c_BPF_ARSH = 0xc0
--  BPF ALU/ALU64 operation code: endianness conversion.
c_BPF_END :: Word8
c_BPF_END = 0xd0

-- Operation codes -- BPF_JMP class:
--  BPF JMP operation code: jump.
c_BPF_JA :: Word8
c_BPF_JA = 0x00
--  BPF JMP operation code: jump if equal.
c_BPF_JEQ :: Word8
c_BPF_JEQ = 0x10
--  BPF JMP operation code: jump if greater than.
c_BPF_JGT :: Word8
c_BPF_JGT = 0x20
--  BPF JMP operation code: jump if greater or equal.
c_BPF_JGE :: Word8
c_BPF_JGE = 0x30
--  BPF JMP operation code: jump if `src` & `reg`.
c_BPF_JSET :: Word8
c_BPF_JSET = 0x40
--  BPF JMP operation code: jump if not equal.
c_BPF_JNE :: Word8
c_BPF_JNE = 0x50
--  BPF JMP operation code: jump if greater than (signed).
c_BPF_JSGT :: Word8
c_BPF_JSGT = 0x60
--  BPF JMP operation code: jump if greater or equal (signed).
c_BPF_JSGE :: Word8
c_BPF_JSGE = 0x70
--  BPF JMP operation code: helper function call.
c_BPF_CALL :: Word8
c_BPF_CALL = 0x80
--  BPF JMP operation code: return from program.
c_BPF_EXIT :: Word8
c_BPF_EXIT = 0x90
--  BPF JMP operation code: jump if lower than.
c_BPF_JLT :: Word8
c_BPF_JLT = 0xa0
--  BPF JMP operation code: jump if lower or equal.
c_BPF_JLE :: Word8
c_BPF_JLE = 0xb0
--  BPF JMP operation code: jump if lower than (signed).
c_BPF_JSLT :: Word8
c_BPF_JSLT = 0xc0
--  BPF JMP operation code: jump if lower or equal (signed).
c_BPF_JSLE :: Word8
c_BPF_JSLE = 0xd0

-- Op codes
-- (Following operation names are not “official”; Linux kernel only
-- combines above flags and does not attribute a name per operation.)

--  BPF opcode: `ldabsb src, dst, imm`.
c_LD_ABS_B :: Word8
c_LD_ABS_B = c_BPF_LD    .|. c_BPF_ABS .|. c_BPF_B
--  BPF opcode: `ldabsh src, dst, imm`.
c_LD_ABS_H :: Word8
c_LD_ABS_H = c_BPF_LD    .|. c_BPF_ABS .|. c_BPF_H
--  BPF opcode: `ldabsw src, dst, imm`.
c_LD_ABS_W :: Word8
c_LD_ABS_W = c_BPF_LD    .|. c_BPF_ABS .|. c_BPF_W
--  BPF opcode: `ldabsdw src, dst, imm`.
c_LD_ABS_DW :: Word8
c_LD_ABS_DW = c_BPF_LD    .|. c_BPF_ABS .|. c_BPF_DW
--  BPF opcode: `ldindb src, dst, imm`.
c_LD_IND_B :: Word8
c_LD_IND_B = c_BPF_LD    .|. c_BPF_IND .|. c_BPF_B
--  BPF opcode: `ldindh src, dst, imm`.
c_LD_IND_H :: Word8
c_LD_IND_H = c_BPF_LD    .|. c_BPF_IND .|. c_BPF_H
--  BPF opcode: `ldindw src, dst, imm`.
c_LD_IND_W :: Word8
c_LD_IND_W = c_BPF_LD    .|. c_BPF_IND .|. c_BPF_W
--  BPF opcode: `ldinddw src, dst, imm`.
c_LD_IND_DW :: Word8
c_LD_IND_DW = c_BPF_LD    .|. c_BPF_IND .|. c_BPF_DW

--  BPF opcode: `lddw dst, imm` --  `dst = imm`.
c_LD_DW_IMM :: Word8
c_LD_DW_IMM = c_BPF_LD    .|. c_BPF_IMM .|. c_BPF_DW
--  BPF opcode: `ldxb dst, [src + off]` --  `dst = (src + off) as u8`.
c_LD_B_REG :: Word8
c_LD_B_REG = c_BPF_LDX   .|. c_BPF_MEM .|. c_BPF_B
--  BPF opcode: `ldxh dst, [src + off]` --  `dst = (src + off) as u16`.
c_LD_H_REG :: Word8
c_LD_H_REG = c_BPF_LDX   .|. c_BPF_MEM .|. c_BPF_H
--  BPF opcode: `ldxw dst, [src + off]` --  `dst = (src + off) as u32`.
c_LD_W_REG :: Word8
c_LD_W_REG = c_BPF_LDX   .|. c_BPF_MEM .|. c_BPF_W
--  BPF opcode: `ldxdw dst, [src + off]` --  `dst = (src + off) as u64`.
c_LD_DW_REG :: Word8
c_LD_DW_REG = c_BPF_LDX   .|. c_BPF_MEM .|. c_BPF_DW
--  BPF opcode: `stb [dst + off], imm` --  `(dst + offset) as u8 = imm`.
c_ST_B_IMM :: Word8
c_ST_B_IMM = c_BPF_ST    .|. c_BPF_MEM .|. c_BPF_B
--  BPF opcode: `sth [dst + off], imm` --  `(dst + offset) as u16 = imm`.
c_ST_H_IMM :: Word8
c_ST_H_IMM = c_BPF_ST    .|. c_BPF_MEM .|. c_BPF_H
--  BPF opcode: `stw [dst + off], imm` --  `(dst + offset) as u32 = imm`.
c_ST_W_IMM :: Word8
c_ST_W_IMM = c_BPF_ST    .|. c_BPF_MEM .|. c_BPF_W
--  BPF opcode: `stdw [dst + off], imm` --  `(dst + offset) as u64 = imm`.
c_ST_DW_IMM :: Word8
c_ST_DW_IMM = c_BPF_ST    .|. c_BPF_MEM .|. c_BPF_DW
--  BPF opcode: `stxb [dst + off], src` --  `(dst + offset) as u8 = src`.
c_ST_B_REG :: Word8
c_ST_B_REG = c_BPF_STX   .|. c_BPF_MEM .|. c_BPF_B
--  BPF opcode: `stxh [dst + off], src` --  `(dst + offset) as u16 = src`.
c_ST_H_REG :: Word8
c_ST_H_REG = c_BPF_STX   .|. c_BPF_MEM .|. c_BPF_H
--  BPF opcode: `stxw [dst + off], src` --  `(dst + offset) as u32 = src`.
c_ST_W_REG :: Word8
c_ST_W_REG = c_BPF_STX   .|. c_BPF_MEM .|. c_BPF_W
--  BPF opcode: `stxdw [dst + off], src` --  `(dst + offset) as u64 = src`.
c_ST_DW_REG :: Word8
c_ST_DW_REG = c_BPF_STX   .|. c_BPF_MEM .|. c_BPF_DW

--  BPF opcode: `stxxaddw [dst + off], src`.
c_ST_W_ATOMIC :: Word8
c_ST_W_ATOMIC = c_BPF_STX   .|. c_BPF_ATOMIC .|. c_BPF_W
--  BPF opcode: `stxxadddw [dst + off], src`.
c_ST_DW_ATOMIC :: Word8
c_ST_DW_ATOMIC = c_BPF_STX   .|. c_BPF_ATOMIC .|. c_BPF_DW

--  BPF opcode: `add32 dst, imm` --  `dst += imm`.
c_ADD32_IMM :: Word8
c_ADD32_IMM = c_BPF_ALU   .|. c_BPF_K   .|. c_BPF_ADD
--  BPF opcode: `add32 dst, src` --  `dst += src`.
c_ADD32_REG :: Word8
c_ADD32_REG = c_BPF_ALU   .|. c_BPF_X   .|. c_BPF_ADD
--  BPF opcode: `sub32 dst, imm` --  `dst -= imm`.
c_SUB32_IMM :: Word8
c_SUB32_IMM = c_BPF_ALU   .|. c_BPF_K   .|. c_BPF_SUB
--  BPF opcode: `sub32 dst, src` --  `dst -= src`.
c_SUB32_REG :: Word8
c_SUB32_REG = c_BPF_ALU   .|. c_BPF_X   .|. c_BPF_SUB
--  BPF opcode: `mul32 dst, imm` --  `dst *= imm`.
c_MUL32_IMM :: Word8
c_MUL32_IMM = c_BPF_ALU   .|. c_BPF_K   .|. c_BPF_MUL
--  BPF opcode: `mul32 dst, src` --  `dst *= src`.
c_MUL32_REG :: Word8
c_MUL32_REG = c_BPF_ALU   .|. c_BPF_X   .|. c_BPF_MUL
--  BPF opcode: `div32 dst, imm` --  `dst /= imm`.
c_DIV32_IMM :: Word8
c_DIV32_IMM = c_BPF_ALU   .|. c_BPF_K   .|. c_BPF_DIV
--  BPF opcode: `div32 dst, src` --  `dst /= src`.
c_DIV32_REG :: Word8
c_DIV32_REG = c_BPF_ALU   .|. c_BPF_X   .|. c_BPF_DIV
--  BPF opcode: `or32 dst, imm` --  `dst |= imm`.
c_OR32_IMM :: Word8
c_OR32_IMM = c_BPF_ALU   .|. c_BPF_K   .|. c_BPF_OR
--  BPF opcode: `or32 dst, src` --  `dst |= src`.
c_OR32_REG :: Word8
c_OR32_REG = c_BPF_ALU   .|. c_BPF_X   .|. c_BPF_OR
--  BPF opcode: `and32 dst, imm` --  `dst &= imm`.
c_AND32_IMM :: Word8
c_AND32_IMM = c_BPF_ALU   .|. c_BPF_K   .|. c_BPF_AND
--  BPF opcode: `and32 dst, src` --  `dst &= src`.
c_AND32_REG :: Word8
c_AND32_REG = c_BPF_ALU   .|. c_BPF_X   .|. c_BPF_AND
--  BPF opcode: `lsh32 dst, imm` --  `dst <<= imm`.
c_LSH32_IMM :: Word8
c_LSH32_IMM = c_BPF_ALU   .|. c_BPF_K   .|. c_BPF_LSH
--  BPF opcode: `lsh32 dst, src` --  `dst <<= src`.
c_LSH32_REG :: Word8
c_LSH32_REG = c_BPF_ALU   .|. c_BPF_X   .|. c_BPF_LSH
--  BPF opcode: `rsh32 dst, imm` --  `dst >>= imm`.
c_RSH32_IMM :: Word8
c_RSH32_IMM = c_BPF_ALU   .|. c_BPF_K   .|. c_BPF_RSH
--  BPF opcode: `rsh32 dst, src` --  `dst >>= src`.
c_RSH32_REG :: Word8
c_RSH32_REG = c_BPF_ALU   .|. c_BPF_X   .|. c_BPF_RSH
--  BPF opcode: `neg32 dst` --  `dst = -dst`.
c_NEG32 :: Word8
c_NEG32 = c_BPF_ALU   .|. c_BPF_NEG
--  BPF opcode: `mod32 dst, imm` --  `dst %= imm`.
c_MOD32_IMM :: Word8
c_MOD32_IMM = c_BPF_ALU   .|. c_BPF_K   .|. c_BPF_MOD
--  BPF opcode: `mod32 dst, src` --  `dst %= src`.
c_MOD32_REG :: Word8
c_MOD32_REG = c_BPF_ALU   .|. c_BPF_X   .|. c_BPF_MOD
--  BPF opcode: `xor32 dst, imm` --  `dst ^= imm`.
c_XOR32_IMM :: Word8
c_XOR32_IMM = c_BPF_ALU   .|. c_BPF_K   .|. c_BPF_XOR
--  BPF opcode: `xor32 dst, src` --  `dst ^= src`.
c_XOR32_REG :: Word8
c_XOR32_REG = c_BPF_ALU   .|. c_BPF_X   .|. c_BPF_XOR
--  BPF opcode: `mov32 dst, imm` --  `dst = imm`.
c_MOV32_IMM :: Word8
c_MOV32_IMM = c_BPF_ALU   .|. c_BPF_K   .|. c_BPF_MOV
--  BPF opcode: `mov32 dst, src` --  `dst = src`.
c_MOV32_REG :: Word8
c_MOV32_REG = c_BPF_ALU   .|. c_BPF_X   .|. c_BPF_MOV
--  BPF opcode: `arsh32 dst, imm` --  `dst >>= imm (arithmetic)`.
c_ARSH32_IMM :: Word8
c_ARSH32_IMM = c_BPF_ALU   .|. c_BPF_K   .|. c_BPF_ARSH
--  BPF opcode: `arsh32 dst, src` --  `dst >>= src (arithmetic)`.
c_ARSH32_REG :: Word8
c_ARSH32_REG = c_BPF_ALU   .|. c_BPF_X   .|. c_BPF_ARSH

--  BPF opcode: `le dst` --  `dst = htole<imm>(dst), with imm in {16, 32, 64}`.
c_LE :: Word8
c_LE = c_BPF_ALU   .|. c_BPF_K   .|. c_BPF_END
--  BPF opcode: `be dst` --  `dst = htobe<imm>(dst), with imm in {16, 32, 64}`.
c_BE :: Word8
c_BE = c_BPF_ALU   .|. c_BPF_X   .|. c_BPF_END

--  BPF opcode: `add64 dst, imm` --  `dst += imm`.
c_ADD64_IMM :: Word8
c_ADD64_IMM = c_BPF_ALU64 .|. c_BPF_K   .|. c_BPF_ADD
--  BPF opcode: `add64 dst, src` --  `dst += src`.
c_ADD64_REG :: Word8
c_ADD64_REG = c_BPF_ALU64 .|. c_BPF_X   .|. c_BPF_ADD
--  BPF opcode: `sub64 dst, imm` --  `dst -= imm`.
c_SUB64_IMM :: Word8
c_SUB64_IMM = c_BPF_ALU64 .|. c_BPF_K   .|. c_BPF_SUB
--  BPF opcode: `sub64 dst, src` --  `dst -= src`.
c_SUB64_REG :: Word8
c_SUB64_REG = c_BPF_ALU64 .|. c_BPF_X   .|. c_BPF_SUB
--  BPF opcode: `div64 dst, imm` --  `dst /= imm`.
c_MUL64_IMM :: Word8
c_MUL64_IMM = c_BPF_ALU64 .|. c_BPF_K   .|. c_BPF_MUL
--  BPF opcode: `div64 dst, src` --  `dst /= src`.
c_MUL64_REG :: Word8
c_MUL64_REG = c_BPF_ALU64 .|. c_BPF_X   .|. c_BPF_MUL
--  BPF opcode: `div64 dst, imm` --  `dst /= imm`.
c_DIV64_IMM :: Word8
c_DIV64_IMM = c_BPF_ALU64 .|. c_BPF_K   .|. c_BPF_DIV
--  BPF opcode: `div64 dst, src` --  `dst /= src`.
c_DIV64_REG :: Word8
c_DIV64_REG = c_BPF_ALU64 .|. c_BPF_X   .|. c_BPF_DIV
--  BPF opcode: `or64 dst, imm` --  `dst |= imm`.
c_OR64_IMM :: Word8
c_OR64_IMM = c_BPF_ALU64 .|. c_BPF_K   .|. c_BPF_OR
--  BPF opcode: `or64 dst, src` --  `dst |= src`.
c_OR64_REG :: Word8
c_OR64_REG = c_BPF_ALU64 .|. c_BPF_X   .|. c_BPF_OR
--  BPF opcode: `and64 dst, imm` --  `dst &= imm`.
c_AND64_IMM :: Word8
c_AND64_IMM = c_BPF_ALU64 .|. c_BPF_K   .|. c_BPF_AND
--  BPF opcode: `and64 dst, src` --  `dst &= src`.
c_AND64_REG :: Word8
c_AND64_REG = c_BPF_ALU64 .|. c_BPF_X   .|. c_BPF_AND
--  BPF opcode: `lsh64 dst, imm` --  `dst <<= imm`.
c_LSH64_IMM :: Word8
c_LSH64_IMM = c_BPF_ALU64 .|. c_BPF_K   .|. c_BPF_LSH
--  BPF opcode: `lsh64 dst, src` --  `dst <<= src`.
c_LSH64_REG :: Word8
c_LSH64_REG = c_BPF_ALU64 .|. c_BPF_X   .|. c_BPF_LSH
--  BPF opcode: `rsh64 dst, imm` --  `dst >>= imm`.
c_RSH64_IMM :: Word8
c_RSH64_IMM = c_BPF_ALU64 .|. c_BPF_K   .|. c_BPF_RSH
--  BPF opcode: `rsh64 dst, src` --  `dst >>= src`.
c_RSH64_REG :: Word8
c_RSH64_REG = c_BPF_ALU64 .|. c_BPF_X   .|. c_BPF_RSH
--  BPF opcode: `neg64 dst, imm` --  `dst = -dst`.
c_NEG64 :: Word8
c_NEG64 = c_BPF_ALU64 .|. c_BPF_NEG
--  BPF opcode: `mod64 dst, imm` --  `dst %= imm`.
c_MOD64_IMM :: Word8
c_MOD64_IMM = c_BPF_ALU64 .|. c_BPF_K   .|. c_BPF_MOD
--  BPF opcode: `mod64 dst, src` --  `dst %= src`.
c_MOD64_REG :: Word8
c_MOD64_REG = c_BPF_ALU64 .|. c_BPF_X   .|. c_BPF_MOD
--  BPF opcode: `xor64 dst, imm` --  `dst ^= imm`.
c_XOR64_IMM :: Word8
c_XOR64_IMM = c_BPF_ALU64 .|. c_BPF_K   .|. c_BPF_XOR
--  BPF opcode: `xor64 dst, src` --  `dst ^= src`.
c_XOR64_REG :: Word8
c_XOR64_REG = c_BPF_ALU64 .|. c_BPF_X   .|. c_BPF_XOR
--  BPF opcode: `mov64 dst, imm` --  `dst = imm`.
c_MOV64_IMM :: Word8
c_MOV64_IMM = c_BPF_ALU64 .|. c_BPF_K   .|. c_BPF_MOV
--  BPF opcode: `mov64 dst, src` --  `dst = src`.
c_MOV64_REG :: Word8
c_MOV64_REG = c_BPF_ALU64 .|. c_BPF_X   .|. c_BPF_MOV
--  BPF opcode: `arsh64 dst, imm` --  `dst >>= imm (arithmetic)`.
c_ARSH64_IMM :: Word8
c_ARSH64_IMM = c_BPF_ALU64 .|. c_BPF_K   .|. c_BPF_ARSH
--  BPF opcode: `arsh64 dst, src` --  `dst >>= src (arithmetic)`.
c_ARSH64_REG :: Word8
c_ARSH64_REG = c_BPF_ALU64 .|. c_BPF_X   .|. c_BPF_ARSH

--  BPF opcode: `ja +off` --  `PC += off`.
c_JA :: Word8
c_JA = c_BPF_JMP   .|. c_BPF_JA
--  BPF opcode: `jeq dst, imm, +off` --  `PC += off if dst == imm`.
c_JEQ_IMM :: Word8
c_JEQ_IMM = c_BPF_JMP   .|. c_BPF_K   .|. c_BPF_JEQ
--  BPF opcode: `jeq dst, src, +off` --  `PC += off if dst == src`.
c_JEQ_REG :: Word8
c_JEQ_REG = c_BPF_JMP   .|. c_BPF_X   .|. c_BPF_JEQ
--  BPF opcode: `jgt dst, imm, +off` --  `PC += off if dst > imm`.
c_JGT_IMM :: Word8
c_JGT_IMM = c_BPF_JMP   .|. c_BPF_K   .|. c_BPF_JGT
--  BPF opcode: `jgt dst, src, +off` --  `PC += off if dst > src`.
c_JGT_REG :: Word8
c_JGT_REG = c_BPF_JMP   .|. c_BPF_X   .|. c_BPF_JGT
--  BPF opcode: `jge dst, imm, +off` --  `PC += off if dst >= imm`.
c_JGE_IMM :: Word8
c_JGE_IMM = c_BPF_JMP   .|. c_BPF_K   .|. c_BPF_JGE
--  BPF opcode: `jge dst, src, +off` --  `PC += off if dst >= src`.
c_JGE_REG :: Word8
c_JGE_REG = c_BPF_JMP   .|. c_BPF_X   .|. c_BPF_JGE
--  BPF opcode: `jlt dst, imm, +off` --  `PC += off if dst < imm`.
c_JLT_IMM :: Word8
c_JLT_IMM = c_BPF_JMP   .|. c_BPF_K   .|. c_BPF_JLT
--  BPF opcode: `jlt dst, src, +off` --  `PC += off if dst < src`.
c_JLT_REG :: Word8
c_JLT_REG = c_BPF_JMP   .|. c_BPF_X   .|. c_BPF_JLT
--  BPF opcode: `jle dst, imm, +off` --  `PC += off if dst <= imm`.
c_JLE_IMM :: Word8
c_JLE_IMM = c_BPF_JMP   .|. c_BPF_K   .|. c_BPF_JLE
--  BPF opcode: `jle dst, src, +off` --  `PC += off if dst <= src`.
c_JLE_REG :: Word8
c_JLE_REG = c_BPF_JMP   .|. c_BPF_X   .|. c_BPF_JLE
--  BPF opcode: `jset dst, imm, +off` --  `PC += off if dst & imm`.
c_JSET_IMM :: Word8
c_JSET_IMM = c_BPF_JMP   .|. c_BPF_K   .|. c_BPF_JSET
--  BPF opcode: `jset dst, src, +off` --  `PC += off if dst & src`.
c_JSET_REG :: Word8
c_JSET_REG = c_BPF_JMP   .|. c_BPF_X   .|. c_BPF_JSET
--  BPF opcode: `jne dst, imm, +off` --  `PC += off if dst != imm`.
c_JNE_IMM :: Word8
c_JNE_IMM = c_BPF_JMP   .|. c_BPF_K   .|. c_BPF_JNE
--  BPF opcode: `jne dst, src, +off` --  `PC += off if dst != src`.
c_JNE_REG :: Word8
c_JNE_REG = c_BPF_JMP   .|. c_BPF_X   .|. c_BPF_JNE
--  BPF opcode: `jsgt dst, imm, +off` --  `PC += off if dst > imm (signed)`.
c_JSGT_IMM :: Word8
c_JSGT_IMM = c_BPF_JMP   .|. c_BPF_K   .|. c_BPF_JSGT
--  BPF opcode: `jsgt dst, src, +off` --  `PC += off if dst > src (signed)`.
c_JSGT_REG :: Word8
c_JSGT_REG = c_BPF_JMP   .|. c_BPF_X   .|. c_BPF_JSGT
--  BPF opcode: `jsge dst, imm, +off` --  `PC += off if dst >= imm (signed)`.
c_JSGE_IMM :: Word8
c_JSGE_IMM = c_BPF_JMP   .|. c_BPF_K   .|. c_BPF_JSGE
--  BPF opcode: `jsge dst, src, +off` --  `PC += off if dst >= src (signed)`.
c_JSGE_REG :: Word8
c_JSGE_REG = c_BPF_JMP   .|. c_BPF_X   .|. c_BPF_JSGE
--  BPF opcode: `jslt dst, imm, +off` --  `PC += off if dst < imm (signed)`.
c_JSLT_IMM :: Word8
c_JSLT_IMM = c_BPF_JMP   .|. c_BPF_K   .|. c_BPF_JSLT
--  BPF opcode: `jslt dst, src, +off` --  `PC += off if dst < src (signed)`.
c_JSLT_REG :: Word8
c_JSLT_REG = c_BPF_JMP   .|. c_BPF_X   .|. c_BPF_JSLT
--  BPF opcode: `jsle dst, imm, +off` --  `PC += off if dst <= imm (signed)`.
c_JSLE_IMM :: Word8
c_JSLE_IMM = c_BPF_JMP   .|. c_BPF_K   .|. c_BPF_JSLE
--  BPF opcode: `jsle dst, src, +off` --  `PC += off if dst <= src (signed)`.
c_JSLE_REG :: Word8
c_JSLE_REG = c_BPF_JMP   .|. c_BPF_X   .|. c_BPF_JSLE

--  BPF opcode: `call imm` --  helper function call to helper with key `imm`.
c_CALL :: Word8
c_CALL = c_BPF_JMP   .|. c_BPF_CALL
--  BPF opcode: `exit` --  `return r0`.
c_EXIT :: Word8
c_EXIT = c_BPF_JMP   .|. c_BPF_EXIT
