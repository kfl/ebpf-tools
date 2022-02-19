module Main where

import Ebpf.Asm
import Ebpf.AsmParser

import Options.Applicative
import Text.Pretty.Simple (pPrint)

data Tool = Dump
          | Assemble
          | Disassemble
          deriving (Eq, Show)

data Options = Options { tool  :: Tool
                       , file  :: String
                       }

options :: ParserInfo Options
options = info (opts <**> helper)
          (fullDesc
           <> progDesc "Assembler for eBPF bytecode")
  where
    opts = Options
      <$> flag' Dump
           (long "dump"
            <> help "Parse file and print an AST")
      <*> argument str (metavar "FILE")



main :: IO ()
main = do
  Options tool file <- execParser options
  case tool of
    Dump -> do res <- parseFromFile file
               case res of
                 Left err -> print err
                 Right prog -> pPrint prog
