{-# LANGUAGE OverloadedStrings #-}
module Main where

import Ebpf.Asm
import Ebpf.AsmParser
import Ebpf.Display()
import qualified Ebpf.Encode as E
import qualified Ebpf.Decode as D
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Internal as B (w2c)
import qualified Data.Binary.Get as BG
import qualified Data.Binary as Bin


import Options.Applicative
import Text.Pretty.Simple (pPrint)
import Text.Printf (printf)
import qualified System.Exit as SE
import Data.Text.Display
import qualified Data.Text as T
import qualified Data.Text.IO as TIO


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
      let out = maybe hexDump B.writeFile outfile
      res <- parseFromFile file
      case res of
        Left err -> SE.die err
        Right prog ->
          case wellformed prog of
            Just err -> SE.die $ "Program not wellformed: " ++ err
            _ -> out $ E.encodeProgram prog

    Disassemble -> do
      let out = maybe TIO.putStrLn TIO.writeFile outfile
      bytes <- BL.readFile file
      case BG.runGetOrFail D.program bytes of
        Left (_, _, err) -> SE.die $ "Could not decode bytes: " ++ err
        Right(_,_, prog) -> out $ displayProgram prog

--    _ -> error "Not implemented yet"


displayProgram :: Program -> T.Text
displayProgram prog =
  T.concat $ map (\i -> display i <> "\n") prog


-- | Print a strict ByteString roughly in the same format as running
-- xxd -c 8 -g 1 bin on it. Corresponding to the encoding of one
-- instruction per line
hexDump :: B.ByteString -> IO ()
hexDump bs = dumpLines 0 bs
  where
  dumpLines :: Int -> B.ByteString -> IO ()
  dumpLines offset bs
    | B.null bs = return ()
    | otherwise = do
        printf "%08x  " offset
        putStrLn $ unwords $ map (printf "%02x") $ B.unpack $ B.take 8 bs
        dumpLines (offset + 8) $ B.drop 8 bs
