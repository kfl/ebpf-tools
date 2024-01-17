module Ebpf.AsmParser where

import Ebpf.Asm
import qualified Data.Char as C
import qualified Data.Map.Strict as M
import Data.Map.Strict (Map)
import Data.Int (Int64)
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

reg :: Parser u Reg
reg = Reg . read <$> lexeme (char 'r' >> many1 digit) <?> "register"

imm :: Parser u Int64
imm = lexeme number <?> "immediate constant"
  where
    number = sign <*> unsigned
    unsigned = (char '0' >> (hex <|> decimal <|> return 0))
               <|> decimal
    hex = read . ("0x" ++) <$> (oneOf "Xx" >> many1 hexDigit)
    decimal = read <$> many1 digit
    sign = (char '-' >> return negate)
           <|> (optional (char '+') >> return id)

splice = lexeme $ char '#' *> char '{' *> many1 alphaNum <* char '}'

regimm = do
  (spliceCon, regCon, immCon) <- getState
  (regCon <$> reg) <|> (immCon <$> imm) <|> (spliceCon <$> splice)

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
         ((,) <$> reg <*> optionMaybe (symbol "+" *> imm))

stores = do
  (mem_sz, bsz) <- [("b", B8), ("h", B16), ("w", B32), ("dw", B64)]
  (x, r_or_i) <- [("x", rSplice), ("", iSplice)]
  let name = "st" ++ x ++ mem_sz
  return (name, do (r, off) <- memref
                   ocomma
                   Store bsz r off <$> r_or_i)
  where
    rSplice = do (spliceCon, regCon, _) <- getState
                 (regCon <$> reg) <|> (spliceCon <$> splice)
    iSplice = do (spliceCon, _, immCon) <- getState
                 (immCon <$> imm) <|> (spliceCon <$> splice)

loads = do
  (mem_sz, bsz) <- [("b", B8), ("h", B16), ("w", B32), ("dw", B64)]
  let name = "ldx" ++ mem_sz
  return (name, do dst <- reg
                   ocomma
                   (src, off) <- memref
                   return $ Load bsz dst src off)


conditionals = do
  jmp <- [Jeq .. Jsle]
  let name = lowercase jmp
  return(name, JCond jmp <$> reg <* ocomma <*> regimm <* ocomma <*> (symbol "+" *> imm)) -- TODO: Do we really want to require the '+' here?


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
                             conditionals ++
                             [ ("ja", Jmp <$> imm),
                               ("jmp", Jmp <$> imm),
                               ("call", Call <$> imm),
                               ("exit", pure Exit)]


program = sc >> many1 instruction <* eof

defaultCons = (error "Splices not allowed", R, Imm)

parse :: String -> Either String Program
parse str = first show $ runParser program defaultCons "<input>" str

parseFromFile :: FilePath -> IO (Either String Program)
parseFromFile filename = first show <$> do
  input <- readFile filename
  return $ runParser program defaultCons filename input
