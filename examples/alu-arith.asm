;; Exercising some 32bit ALU instructions
mov32 r0, 0
mov32 r1, 1
mov32 r2, 2
mov32 r3, 3
mov32 r4, 4
mov32 r5, 5
mov32 r6, 6
mov32 r7, 7
mov32 r8, 8
mov32 r9, 9
;; r0 == 0

add32 r0, 23
add64 r0, r7
;; r0 == 30

sub32 r0, 13
sub32 r0, r1
;; r0 == 16

mul32 r0, 7
mul32 r0, r3
;; r0 == 336

div32 r0, 2
div32 r0, r4
;; r0 == 42

exit
;; r0 == 0x2a
