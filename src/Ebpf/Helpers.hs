module Ebpf.Helpers where

import Ebpf.Asm

r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10 :: Reg
[r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10] = map Reg [0 .. 10]

add64_i dst imm = Binary B64 Add  dst (Right imm)
add64_r dst src = Binary B64 Add dst (Left src)
sub64_i dst imm = Binary B64 Sub  dst (Right imm)
sub64_r dst src = Binary B64 Sub dst (Left src)
mul64_i dst imm = Binary B64 Mul  dst (Right imm)
mul64_r dst src = Binary B64 Mul dst (Left src)
div64_i dst imm = Binary B64 Div  dst (Right imm)
div64_r dst src = Binary B64 Div dst (Left src)
or64_i dst imm = Binary B64 Or  dst (Right imm)
or64_r dst src = Binary B64 Or dst (Left src)
and64_i dst imm = Binary B64 And  dst (Right imm)
and64_r dst src = Binary B64 And dst (Left src)
lsh64_i dst imm = Binary B64 Lsh  dst (Right imm)
lsh64_r dst src = Binary B64 Lsh dst (Left src)
rsh64_i dst imm = Binary B64 Rsh  dst (Right imm)
rsh64_r dst src = Binary B64 Rsh dst (Left src)
mod64_i dst imm = Binary B64 Mod  dst (Right imm)
mod64_r dst src = Binary B64 Mod dst (Left src)
xor64_i dst imm = Binary B64 Xor  dst (Right imm)
xor64_r dst src = Binary B64 Xor dst (Left src)
mov64_i dst imm = Binary B64 Mov  dst (Right imm)
mov64_r dst src = Binary B64 Mov dst (Left src)
arsh64_i dst imm = Binary B64 Arsh  dst (Right imm)
arsh64_r dst src = Binary B64 Arsh dst (Left src)

add32_i dst imm = Binary B32 Add  dst (Right imm)
add32_r dst src = Binary B32 Add dst (Left src)
sub32_i dst imm = Binary B32 Sub  dst (Right imm)
sub32_r dst src = Binary B32 Sub dst (Left src)
mul32_i dst imm = Binary B32 Mul  dst (Right imm)
mul32_r dst src = Binary B32 Mul dst (Left src)
div32_i dst imm = Binary B32 Div  dst (Right imm)
div32_r dst src = Binary B32 Div dst (Left src)
or32_i dst imm = Binary B32 Or  dst (Right imm)
or32_r dst src = Binary B32 Or dst (Left src)
and32_i dst imm = Binary B32 And  dst (Right imm)
and32_r dst src = Binary B32 And dst (Left src)
lsh32_i dst imm = Binary B32 Lsh  dst (Right imm)
lsh32_r dst src = Binary B32 Lsh dst (Left src)
rsh32_i dst imm = Binary B32 Rsh  dst (Right imm)
rsh32_r dst src = Binary B32 Rsh dst (Left src)
mod32_i dst imm = Binary B32 Mod  dst (Right imm)
mod32_r dst src = Binary B32 Mod dst (Left src)
xor32_i dst imm = Binary B32 Xor  dst (Right imm)
xor32_r dst src = Binary B32 Xor dst (Left src)
mov32_i dst imm = Binary B32 Mov  dst (Right imm)
mov32_r dst src = Binary B32 Mov dst (Left src)
arsh32_i dst imm = Binary B32 Arsh  dst (Right imm)
arsh32_r dst src = Binary B32 Arsh dst (Left src)

neg64 dst = Unary B64 Neg dst
neg32 dst = Unary B32 Neg dst
le16 dst  = Unary B16 Le dst
le32 dst  = Unary B32 Le dst
le64 dst  = Unary B64 Le dst
be16 dst  = Unary B16 Be dst
be32 dst  = Unary B32 Be dst
be64 dst  = Unary B64 Be dst


lddw dst imm = LoadImm dst imm
loadMapFd dst imm = LoadMapFd dst imm

ldxw dst src off = Load B32 dst src (Just off)
ldxh dst src off = Load B16 dst src (Just off)
ldxb dst src off = Load B8 dst src (Just off)
ldxdw dst src off = Load B64 dst src (Just off)

stw dst off imm = Store B32 dst (Just off) (Right imm)
sth dst off imm = Store B16 dst (Just off) (Right imm)
stb dst off imm = Store B8 dst (Just off) (Right imm)
stdw dst off imm = Store B64 dst (Just off) (Right imm)

stxw dst off src = Store B32 dst (Just off) (Left src)
stxh dst off src = Store B16 dst (Just off) (Left src)
stxb dst off src = Store B8 dst (Just off) (Left src)
stxdw dst off src = Store B64 dst (Just off) (Left src)

ja off = Jmp off
jmp off = Jmp off

jeq_i dst imm off = JCond Jeq dst (Right imm) off
jeq_r dst src off = JCond Jeq dst (Left src) off
jgt_i dst imm off = JCond Jgt dst (Right imm) off
jgt_r dst src off = JCond Jgt dst (Left src) off
jge_i dst imm off = JCond Jge dst (Right imm) off
jge_r dst src off = JCond Jge dst (Left src) off
jlt_i dst imm off = JCond Jlt dst (Right imm) off
jlt_r dst src off = JCond Jlt dst (Left src) off
jle_i dst imm off = JCond Jle dst (Right imm) off
jle_r dst src off = JCond Jle dst (Left src) off
jset_i dst imm off = JCond Jset dst (Right imm) off
jset_r dst src off = JCond Jset dst (Left src) off
jne_i dst imm off = JCond Jne dst (Right imm) off
jne_r dst src off = JCond Jne dst (Left src) off
jsgt_i dst imm off = JCond Jsgt dst (Right imm) off
jsgt_r dst src off = JCond Jsgt dst (Left src) off
jsge_i dst imm off = JCond Jsge dst (Right imm) off
jsge_r dst src off = JCond Jsge dst (Left src) off
jslt_i dst imm off = JCond Jslt dst (Right imm) off
jslt_r dst src off = JCond Jslt dst (Left src) off
jsle_i dst imm off = JCond Jsle dst (Right imm) off
jsle_r dst src off = JCond Jsle dst (Left src) off

call f = Call f
exit = Exit
