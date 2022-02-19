module Main where

import Ebpf.Asm
import Ebpf.AsmParser

main :: IO ()
main = do
  putStrLn "Lets parse some eBPF"
