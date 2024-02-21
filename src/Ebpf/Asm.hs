{-# LANGUAGE DeriveDataTypeable #-}
module Ebpf.Asm where

import Data.Int (Int64, Int32)
import Data.Foldable (asum)
import Data.Data


data BinAlu = Add | Sub | Mul | Div | Or | And | Lsh | Rsh | Mod | Xor
  | Mov | Arsh
  deriving (Eq, Show, Ord, Enum, Data)

data UnAlu = Neg | Le | Be
  deriving (Eq, Show, Ord, Enum, Data)

data BSize = B8 | B16 | B32 | B64
  deriving (Eq, Show, Ord, Enum, Data)

data Jcmp = Jeq | Jgt | Jge | Jlt | Jle | Jset | Jne | Jsgt | Jsge | Jslt | Jsle
  deriving (Eq, Show, Ord, Enum, Data)

--data Reg = R0 | R1 | R2 | R3 | R4 | R5 | R6 | R7 | R8 | R9 | R10
newtype Reg = Reg Int deriving (Eq, Show, Ord, Data)
type Imm = Int64
data RegImm = R Reg | Imm Imm deriving (Eq, Show, Ord, Data)
type Offset = Int64
type MemoryOffset = Offset
type CodeOffset = Offset
type HelperId = Int32

-- TODO support atomic operations
-- TODO support absolute and indirect loads
-- TODO support tail calls

data Inst reg imm regimm extern =
    Binary BSize BinAlu reg regimm
  | Unary BSize UnAlu reg
  | Store BSize reg (Maybe MemoryOffset) regimm
  | Load BSize reg reg (Maybe MemoryOffset)
  | LoadImm reg imm
  | LoadMapFd reg imm
  | LoadAbs BSize imm
  | LoadInd BSize reg imm
  | JCond Jcmp reg regimm CodeOffset
  | Jmp CodeOffset
  | Call extern
  | Exit
  deriving (Eq, Show, Ord, Data)

type Instruction = Inst Reg Imm RegImm HelperId

type Program = [Instruction]


wellformed :: Program -> Maybe String
wellformed instrs = asum $ fmap wfInst instrs
  where
    wfReg (Reg n) | 0 <= n && n < 11 = Nothing
                  | otherwise = Just $ "Invalid register: r"++show n
    wfRegImm (R r) = wfReg r
    wfRegImm (Imm imm) | -2^31 <= imm && imm < 2^31 = Nothing
                       | otherwise = Just $ "Invalid immediate: "++show imm
    wfOffset n | -2^15 <= n && n < 2^15 = Nothing
               | otherwise = Just $ "Invalid immediate: "++show n
    wfInst inst =
      case inst of
        Binary bs opr _ _ | bs == B8 || bs == B16 ->
                            return $ concat ["Invalid byte size '", show bs
                                            , "' for operation: ", show opr]
        Binary _ _ r ri -> asum [wfReg r, wfRegImm ri]
        Unary bs@B8 opr _ -> return $ concat ["Invalid byte size '", show bs
                                            , "' for operation: ", show opr]
        Unary B16 Neg _ -> return "Invalid byte size 'B16' for operation: Neg"
        Unary _ _ r -> wfReg r
        Store _ dst off src -> asum [wfReg dst, off >>= wfOffset, wfRegImm src]
        Load _ dst src off -> asum [wfReg dst, off >>= wfOffset, wfReg src]
        LoadImm dst _ -> wfReg dst
        LoadMapFd dst _ -> wfReg dst
        LoadAbs _ _ -> Nothing -- should immediate be checked?
        LoadInd _ src _ -> wfReg src
        -- TODO check that off is within bounds
        JCond _ lhs rhs off -> asum [wfReg lhs, wfRegImm rhs, wfOffset off]
        Jmp off -> wfOffset off

        _ -> Nothing
  -- TODO Call Imm
  -- TODO Exit
