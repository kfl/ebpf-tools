{-# LANGUAGE NamedFieldPuns #-}
module Ebpf.AsmParser where

import Ebpf.Asm
import qualified Data.Char as C
import qualified Data.Map.Strict as M
import Data.Map.Strict (Map)
import Data.Int (Int64, Int32)
import Data.Bifunctor (first)

import Text.Parsec
import qualified Text.Parsec as PS

type Parser u a = Parsec String u a

ignore :: Parser u a -> Parser u ()
ignore p = p >> return ()

comment = ignore $ char ';' >> manyTill anyChar (try endOfLine)

sc = skipMany (comment <|> ignore space)

lexeme :: Parser u a -> Parser u a
lexeme p = p <* sc

symbol s = lexeme $ string s

operator = lexeme $ many1 alphaNum

rawReg :: Parser u Reg
rawReg = Reg . read <$> lexeme (char 'r' >> many1 digit) <?> "register"

rawImm :: Parser u Int64
rawImm = lexeme number <?> "immediate constant"
  where
    number = sign <*> unsigned
    unsigned = (char '0' >> (hex <|> decimal <|> return 0))
               <|> decimal
    hex = read . ("0x" ++) <$> (oneOf "Xx" >> many1 hexDigit)
    decimal = read <$> many1 digit
    sign = (char '-' >> return negate)
           <|> (optional (char '+') >> return id)

memoryOffset = rawImm
codeOffset = rawImm

rawImm32 :: Parser u Int32
rawImm32 = lexeme number <?> "extern function"
  where
    number = sign <*> unsigned
    unsigned = (char '0' >> (hex <|> decimal <|> return 0))
               <|> decimal
    hex = read . ("0x" ++) <$> (oneOf "Xx" >> many1 hexDigit)
    decimal = read <$> many1 digit
    sign = (char '-' >> return negate)
           <|> (optional (char '+') >> return id)

-- splice = lexeme $ char '#' *> char '{' *> ident <* char '}'
splice = lexeme $ char '$' *> ident
  where ident = (:) <$> letter <*> (many (alphaNum <|> oneOf "_'"))

reg = do
  S {onlyReg, varReg} <- getState
  (onlyReg <$> rawReg) <|> (varReg <$> splice)

imm = do
  S {onlyImm, varImm} <- getState
  (onlyImm <$> rawImm) <|> (varImm <$> splice)

regimm = do
  S {vRegImm, rRegImm, iRegImm} <- getState
  (rRegImm <$> rawReg) <|> (iRegImm <$> rawImm) <|> (vRegImm <$> splice)

extern = do
  S {iHelperId, vHelperId} <- getState
  (iHelperId <$> rawImm32) <|> (vHelperId <$> splice)

ocomma = lexeme . optional $ char ','

lowercase opr = map C.toLower $ show opr

binAlus = do
  alu <- [Add .. Arsh]
  (post, sz) <- [("32", B32), ("64", B64), ("", B64)]
  let name = lowercase alu ++ post
  return (name, Binary sz alu <$> reg <* ocomma <*> regimm)


unAlus = do
 alu <- [Neg .. Be]
 (post, sz) <- case alu of
                 Neg -> [("32", B32), ("64", B64), ("", B64)]
                 _ -> [("16", B16), ("32", B32), ("64", B64)]
 let name = lowercase alu ++ post
 return (name, Unary sz alu <$> reg)


memref = between (symbol "[") (symbol "]")
         ((,) <$> reg <*> optionMaybe (symbol "+" *> memoryOffset))

stores = do
  (mem_sz, bsz) <- [("b", B8), ("h", B16), ("w", B32), ("dw", B64)]
  (x, r_or_i) <- [("x", rSplice), ("", iSplice)]
  let name = "st" ++ x ++ mem_sz
  return (name, do (r, off) <- memref
                   ocomma
                   Store bsz r off <$> r_or_i)
  where
    rSplice = do S {vRegImm, rRegImm} <- getState
                 (rRegImm <$> rawReg) <|> (vRegImm <$> splice)
    iSplice = do S {vRegImm, iRegImm} <- getState
                 (iRegImm <$> rawImm) <|> (vRegImm <$> splice)

loads = do
  (mem_sz, bsz) <- [("b", B8), ("h", B16), ("w", B32), ("dw", B64)]
  let name = "ldx" ++ mem_sz
  return (name, do dst <- reg
                   ocomma
                   (src, off) <- memref
                   return $ Load bsz dst src off)

ldabs = do
  (mem_sz, bsz) <- [("b", B8), ("h", B16), ("w", B32), ("dw", B64)]
  let name = "ldabs" ++ mem_sz
  return (name, do off <- imm
                   return $ LoadAbs bsz off)

ldind = do
  (mem_sz, bsz) <- [("b", B8), ("h", B16), ("w", B32), ("dw", B64)]
  let name = "ldind" ++ mem_sz
  return (name, do src <- reg
                   ocomma
                   off <- imm
                   return $ LoadInd bsz src off)

conditionals = do
  jmp <- [Jeq .. Jsle]
  let name = lowercase jmp
  return(name, JCond jmp <$> reg <* ocomma <*> regimm <* ocomma <*> (symbol "+" *> codeOffset)) -- TODO: Do we really want to require the '+' here?

instruction = do
  opr <- operator
  case M.lookup opr operators of
    Just argP -> argP
    _ -> fail $ "Unknown operator: " ++ opr
  where
    operators = M.fromList $ binAlus ++
                             unAlus ++
                             stores ++
                             loads ++ [ ("lddw", LoadImm <$> reg <* ocomma <*> imm)] ++
                             [ ("lmfd", LoadMapFd <$> reg <* ocomma <*> imm) ] ++
                             ldabs ++
                             ldind ++
                             conditionals ++
                             [ ("ja", Jmp <$> codeOffset),
                               ("jmp", Jmp <$> codeOffset),
                               ("call", Call <$> extern),
                               ("exit", pure Exit)]


program = sc >> many1 instruction <* eof

-- TODO the naming of the splice stuff is clunky
data SpliceConstructors reg imm regimm extern = S { onlyReg :: Reg -> reg
                                                  , varReg :: String -> reg
                                                  , onlyImm :: Imm -> imm
                                                  , varImm :: String -> imm
                                                  , iHelperId :: HelperId -> extern
                                                  , vHelperId :: String -> extern
                                                  , rRegImm :: Reg -> regimm
                                                  , iRegImm :: Imm -> regimm
                                                  , vRegImm :: String -> regimm
                                                  }
defaultSpliceCons =
  S { onlyReg = id
    , varReg = don't
    , onlyImm = id
    , varImm = don't
    , iHelperId = id
    , vHelperId = don't
    , rRegImm = R
    , iRegImm = Imm
    , vRegImm = don't }
  where don't = error "Splices not allowed"

parse :: String -> Either String Program
parse str = first show $ runParser program defaultSpliceCons "<input>" str

parseFromFile :: FilePath -> IO (Either String Program)
parseFromFile filename = first show <$> do
  input <- readFile filename
  return $ runParser program defaultSpliceCons filename input
