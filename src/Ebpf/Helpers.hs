module Ebpf.Helpers where

import Ebpf.Asm

r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10 :: Reg
[r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10] = map Reg [0 .. 10]
