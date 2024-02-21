{- HLINT ignore "Use camelCase" -}
{- HLINT ignore "Eta reduce" -}
module Ebpf.Helpers where

import Ebpf.Asm
import Data.Int (Int16, Int32)

type Imm32 = Int32
type Offset16 = Int16

r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10 :: Reg
[r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10] = map Reg [0 .. 10]

add64_i :: Reg -> Imm32 -> Instruction
add64_i dst imm = Binary B64 Add dst (Imm $ fromIntegral imm)
add64_r :: Reg -> Reg -> Instruction
add64_r dst src = Binary B64 Add dst (R src)
sub64_i :: Reg -> Imm32 -> Instruction
sub64_i dst imm = Binary B64 Sub dst (Imm $ fromIntegral imm)
sub64_r :: Reg -> Reg -> Instruction
sub64_r dst src = Binary B64 Sub dst (R src)
mul64_i :: Reg -> Imm32 -> Instruction
mul64_i dst imm = Binary B64 Mul dst (Imm $ fromIntegral imm)
mul64_r :: Reg -> Reg -> Instruction
mul64_r dst src = Binary B64 Mul dst (R src)
div64_i :: Reg -> Imm32 -> Instruction
div64_i dst imm = Binary B64 Div dst (Imm $ fromIntegral imm)
div64_r :: Reg -> Reg -> Instruction
div64_r dst src = Binary B64 Div dst (R src)
or64_i :: Reg -> Imm32 -> Instruction
or64_i dst imm = Binary B64 Or dst (Imm $ fromIntegral imm)
or64_r :: Reg -> Reg -> Instruction
or64_r dst src = Binary B64 Or dst (R src)
and64_i :: Reg -> Imm32 -> Instruction
and64_i dst imm = Binary B64 And dst (Imm $ fromIntegral imm)
and64_r :: Reg -> Reg -> Instruction
and64_r dst src = Binary B64 And dst (R src)
lsh64_i :: Reg -> Imm32 -> Instruction
lsh64_i dst imm = Binary B64 Lsh dst (Imm $ fromIntegral imm)
lsh64_r :: Reg -> Reg -> Instruction
lsh64_r dst src = Binary B64 Lsh dst (R src)
rsh64_i :: Reg -> Imm32 -> Instruction
rsh64_i dst imm = Binary B64 Rsh dst (Imm $ fromIntegral imm)
rsh64_r :: Reg -> Reg -> Instruction
rsh64_r dst src = Binary B64 Rsh dst (R src)
mod64_i :: Reg -> Imm32 -> Instruction
mod64_i dst imm = Binary B64 Mod dst (Imm $ fromIntegral imm)
mod64_r :: Reg -> Reg -> Instruction
mod64_r dst src = Binary B64 Mod dst (R src)
xor64_i :: Reg -> Imm32 -> Instruction
xor64_i dst imm = Binary B64 Xor dst (Imm $ fromIntegral imm)
xor64_r :: Reg -> Reg -> Instruction
xor64_r dst src = Binary B64 Xor dst (R src)
mov64_i :: Reg -> Imm32 -> Instruction
mov64_i dst imm = Binary B64 Mov dst (Imm $ fromIntegral imm)
mov64_r :: Reg -> Reg -> Instruction
mov64_r dst src = Binary B64 Mov dst (R src)
arsh64_i :: Reg -> Imm32 -> Instruction
arsh64_i dst imm = Binary B64 Arsh dst (Imm $ fromIntegral imm)
arsh64_r :: Reg -> Reg -> Instruction
arsh64_r dst src = Binary B64 Arsh dst (R src)

add32_i :: Reg -> Imm32 -> Instruction
add32_i dst imm = Binary B32 Add dst (Imm $ fromIntegral imm)
add32_r :: Reg -> Reg -> Instruction
add32_r dst src = Binary B32 Add dst (R src)
sub32_i :: Reg -> Imm32 -> Instruction
sub32_i dst imm = Binary B32 Sub dst (Imm $ fromIntegral imm)
sub32_r :: Reg -> Reg -> Instruction
sub32_r dst src = Binary B32 Sub dst (R src)
mul32_i :: Reg -> Imm32 -> Instruction
mul32_i dst imm = Binary B32 Mul dst (Imm $ fromIntegral imm)
mul32_r :: Reg -> Reg -> Instruction
mul32_r dst src = Binary B32 Mul dst (R src)
div32_i :: Reg -> Imm32 -> Instruction
div32_i dst imm = Binary B32 Div dst (Imm $ fromIntegral imm)
div32_r :: Reg -> Reg -> Instruction
div32_r dst src = Binary B32 Div dst (R src)
or32_i :: Reg -> Imm32 -> Instruction
or32_i dst imm = Binary B32 Or dst (Imm $ fromIntegral imm)
or32_r :: Reg -> Reg -> Instruction
or32_r dst src = Binary B32 Or dst (R src)
and32_i :: Reg -> Imm32 -> Instruction
and32_i dst imm = Binary B32 And dst (Imm $ fromIntegral imm)
and32_r :: Reg -> Reg -> Instruction
and32_r dst src = Binary B32 And dst (R src)
lsh32_i :: Reg -> Imm32 -> Instruction
lsh32_i dst imm = Binary B32 Lsh dst (Imm $ fromIntegral imm)
lsh32_r :: Reg -> Reg -> Instruction
lsh32_r dst src = Binary B32 Lsh dst (R src)
rsh32_i :: Reg -> Imm32 -> Instruction
rsh32_i dst imm = Binary B32 Rsh dst (Imm $ fromIntegral imm)
rsh32_r :: Reg -> Reg -> Instruction
rsh32_r dst src = Binary B32 Rsh dst (R src)
mod32_i :: Reg -> Imm32 -> Instruction
mod32_i dst imm = Binary B32 Mod dst (Imm $ fromIntegral imm)
mod32_r :: Reg -> Reg -> Instruction
mod32_r dst src = Binary B32 Mod dst (R src)
xor32_i :: Reg -> Imm32 -> Instruction
xor32_i dst imm = Binary B32 Xor dst (Imm $ fromIntegral imm)
xor32_r :: Reg -> Reg -> Instruction
xor32_r dst src = Binary B32 Xor dst (R src)
mov32_i :: Reg -> Imm32 -> Instruction
mov32_i dst imm = Binary B32 Mov dst (Imm $ fromIntegral imm)
mov32_r :: Reg -> Reg -> Instruction
mov32_r dst src = Binary B32 Mov dst (R src)
arsh32_i :: Reg -> Imm32 -> Instruction
arsh32_i dst imm = Binary B32 Arsh dst (Imm $ fromIntegral imm)
arsh32_r :: Reg -> Reg -> Instruction
arsh32_r dst src = Binary B32 Arsh dst (R src)

neg64 :: Reg -> Instruction
neg64 dst = Unary B64 Neg dst
neg32 :: Reg -> Instruction
neg32 dst = Unary B32 Neg dst
le16 :: Reg -> Instruction
le16 dst  = Unary B16 Le dst
le32 :: Reg -> Instruction
le32 dst  = Unary B32 Le dst
le64 :: Reg -> Instruction
le64 dst  = Unary B64 Le dst
be16 :: Reg -> Instruction
be16 dst  = Unary B16 Be dst
be32 :: Reg -> Instruction
be32 dst  = Unary B32 Be dst
be64 :: Reg -> Instruction
be64 dst  = Unary B64 Be dst


lddw :: Reg -> Imm -> Instruction
lddw dst imm = LoadImm dst imm
loadMapFd :: Reg -> Imm -> Instruction
loadMapFd dst imm = LoadMapFd dst imm

memOffset off | off /= 0 = Just $ fromIntegral off
              | otherwise = Nothing

ldxw :: Reg -> Reg -> Offset16 -> Instruction
ldxw dst src off = Load B32 dst src (memOffset off)
ldxh :: Reg -> Reg -> Offset16 -> Instruction
ldxh dst src off = Load B16 dst src (memOffset off)
ldxb :: Reg -> Reg -> Offset16 -> Instruction
ldxb dst src off = Load B8 dst src (memOffset off)
ldxdw :: Reg -> Reg -> Offset16 -> Instruction
ldxdw dst src off = Load B64 dst src (memOffset off)

ldabsw :: Imm32 -> Instruction
ldabsw imm = LoadAbs B32 $ fromIntegral imm
ldabsh :: Imm32 -> Instruction
ldabsh imm = LoadAbs B16 $ fromIntegral imm
ldabsb :: Imm32 -> Instruction
ldabsb imm = LoadAbs B8 $ fromIntegral imm
ldabsdw :: Imm32 -> Instruction
ldabsdw imm = LoadAbs B64 $ fromIntegral imm

ldindw :: Reg -> Imm32 -> Instruction
ldindw src imm = LoadInd B32 src $ fromIntegral imm
ldindh :: Reg -> Imm32 -> Instruction
ldindh src imm = LoadInd B16 src $ fromIntegral imm
ldindb :: Reg -> Imm32 -> Instruction
ldindb src imm = LoadInd B8 src $ fromIntegral imm
ldinddw :: Reg -> Imm32 -> Instruction
ldinddw src imm = LoadInd B64 src $ fromIntegral imm

stw :: Reg -> Offset16 -> Imm32 -> Instruction
stw dst off imm = Store B32 dst (memOffset off) (Imm $ fromIntegral imm)
sth :: Reg -> Offset16 -> Imm32 -> Instruction
sth dst off imm = Store B16 dst (memOffset off) (Imm $ fromIntegral imm)
stb :: Reg -> Offset16 -> Imm32 -> Instruction
stb dst off imm = Store B8 dst (memOffset off) (Imm $ fromIntegral imm)
stdw :: Reg -> Offset16 -> Imm32 -> Instruction
stdw dst off imm = Store B64 dst (memOffset off) (Imm $ fromIntegral imm)

stxw :: Reg -> Offset16 -> Reg -> Instruction
stxw dst off src = Store B32 dst (memOffset off) (R src)
stxh :: Reg -> Offset16 -> Reg -> Instruction
stxh dst off src = Store B16 dst (memOffset off) (R src)
stxb :: Reg -> Offset16 -> Reg -> Instruction
stxb dst off src = Store B8 dst (memOffset off) (R src)
stxdw :: Reg -> Offset16 -> Reg -> Instruction
stxdw dst off src = Store B64 dst (memOffset off) (R src)

ja :: Offset16 -> Instruction
ja off = Jmp (fromIntegral off)
jmp :: Offset16 -> Instruction
jmp off = Jmp (fromIntegral off)

jeq_i :: Reg -> Imm32 -> Offset16 -> Instruction
jeq_i dst imm off = JCond Jeq dst (Imm $ fromIntegral imm) (fromIntegral off)
jeq_r :: Reg -> Reg -> Offset16 -> Instruction
jeq_r dst src off = JCond Jeq dst (R src) (fromIntegral off)
jgt_i :: Reg -> Imm32 -> Offset16 -> Instruction
jgt_i dst imm off = JCond Jgt dst (Imm $ fromIntegral imm) (fromIntegral off)
jgt_r :: Reg -> Reg -> Offset16 -> Instruction
jgt_r dst src off = JCond Jgt dst (R src) (fromIntegral off)
jge_i :: Reg -> Imm32 -> Offset16 -> Instruction
jge_i dst imm off = JCond Jge dst (Imm $ fromIntegral imm) (fromIntegral off)
jge_r :: Reg -> Reg -> Offset16 -> Instruction
jge_r dst src off = JCond Jge dst (R src) (fromIntegral off)
jlt_i :: Reg -> Imm32 -> Offset16 -> Instruction
jlt_i dst imm off = JCond Jlt dst (Imm $ fromIntegral imm) (fromIntegral off)
jlt_r :: Reg -> Reg -> Offset16 -> Instruction
jlt_r dst src off = JCond Jlt dst (R src) (fromIntegral off)
jle_i :: Reg -> Imm32 -> Offset16 -> Instruction
jle_i dst imm off = JCond Jle dst (Imm $ fromIntegral imm) (fromIntegral off)
jle_r :: Reg -> Reg -> Offset16 -> Instruction
jle_r dst src off = JCond Jle dst (R src) (fromIntegral off)
jset_i :: Reg -> Imm32 -> Offset16 -> Instruction
jset_i dst imm off = JCond Jset dst (Imm $ fromIntegral imm) (fromIntegral off)
jset_r :: Reg -> Reg -> Offset16 -> Instruction
jset_r dst src off = JCond Jset dst (R src) (fromIntegral off)
jne_i :: Reg -> Imm32 -> Offset16 -> Instruction
jne_i dst imm off = JCond Jne dst (Imm $ fromIntegral imm) (fromIntegral off)
jne_r :: Reg -> Reg -> Offset16 -> Instruction
jne_r dst src off = JCond Jne dst (R src) (fromIntegral off)
jsgt_i :: Reg -> Imm32 -> Offset16 -> Instruction
jsgt_i dst imm off = JCond Jsgt dst (Imm $ fromIntegral imm) (fromIntegral off)
jsgt_r :: Reg -> Reg -> Offset16 -> Instruction
jsgt_r dst src off = JCond Jsgt dst (R src) (fromIntegral off)
jsge_i :: Reg -> Imm32 -> Offset16 -> Instruction
jsge_i dst imm off = JCond Jsge dst (Imm $ fromIntegral imm) (fromIntegral off)
jsge_r :: Reg -> Reg -> Offset16 -> Instruction
jsge_r dst src off = JCond Jsge dst (R src) (fromIntegral off)
jslt_i :: Reg -> Imm32 -> Offset16 -> Instruction
jslt_i dst imm off = JCond Jslt dst (Imm $ fromIntegral imm) (fromIntegral off)
jslt_r :: Reg -> Reg -> Offset16 -> Instruction
jslt_r dst src off = JCond Jslt dst (R src) (fromIntegral off)
jsle_i :: Reg -> Imm32 -> Offset16 -> Instruction
jsle_i dst imm off = JCond Jsle dst (Imm $ fromIntegral imm) (fromIntegral off)
jsle_r :: Reg -> Reg -> Offset16 -> Instruction
jsle_r dst src off = JCond Jsle dst (R src) (fromIntegral off)

call :: Imm32 -> Instruction
call f = Call $ fromIntegral f
exit :: Instruction
exit = Exit
