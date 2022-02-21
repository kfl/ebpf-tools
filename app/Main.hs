module Main where

import Ebpf.Asm
import Ebpf.AsmParser
import qualified Ebpf.Encode as E
import qualified Data.ByteString as B

import Options.Applicative
import Text.Pretty.Simple (pPrint)

data Tool = Dump
          | Assemble
          | Disassemble
          deriving (Eq, Show)

data Options = Options { tool  :: Tool
                       , outfile :: Maybe FilePath
                       , file  :: FilePath
                       } deriving Show

options :: ParserInfo Options
options = info (opts <**> helper)
          (fullDesc
           <> progDesc "Assembler and disassembler for eBPF bytecode")
  where
    opts = Options
      <$> tool
      <*> output
      <*> argument str (metavar "INFILE")

    tool = flag' Assemble (long "assemble"
                           <> short 'a'
                           <> help "Parse asm file and write bytecode to output")
           <|>
           flag' Disassemble (long "disassemble"
                              <> short 'd'
                              <> help "Parse bytecode file and write assembly to output")
           <|>
           flag' Dump (long "dump"
                       <> help "Parse asm file and print an AST")

    output = optional $ strOption (long "output"
                                   <> short 'o'
                                   <> metavar "OUTFILE"
                                   <> help "Write output to OUTFILE (writes to stdout if not given)" )



main :: IO ()
main = do
  Options tool outfile file <- execParser options
  case tool of
    Dump -> do
      res <- parseFromFile file
      case res of
        Left err -> print err
        Right prog -> pPrint prog
    Assemble -> do
      res <- parseFromFile file
      case res of
        Left err -> print err
        Right prog ->
          case outfile of
            Nothing ->
              -- TODO Print hexdump to stdout
              print "Need a file for binary output"
            Just ofile ->
              B.writeFile ofile $ E.encodeProgram prog


    _ -> error "Not implemented yet"
