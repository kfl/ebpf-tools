module Ebpf.Quote (ebpf) where

import qualified Language.Haskell.TH as TH
import qualified Language.Haskell.TH.Syntax as THS
import Language.Haskell.TH.Quote

import qualified Ebpf.Asm as A
import qualified Ebpf.AsmParser as Parser
import qualified Text.Parsec as P
import qualified Text.Parsec.Pos as P

ebpf  :: QuasiQuoter
ebpf  =  QuasiQuoter { quoteExp = quoteEbpfPrograms
                     , quotePat = error "Not allowed in patterns"
                     , quoteType = error "Not allowed in types"
                     , quoteDec  = error "Not allowed in declarations"
                     }

location' :: TH.Q P.SourcePos
location' = aux <$> TH.location
  where
    aux :: TH.Loc -> P.SourcePos
    aux loc = uncurry (P.newPos (TH.loc_filename loc)) (TH.loc_start loc)

parseProgram :: MonadFail m => P.SourcePos -> String -> m A.Program
parseProgram pos s =
    case P.runParser positionedProgram True "" s of
      Left err   -> fail $ show err
      Right prog -> return prog
  where
    positionedProgram = P.setPosition pos *> Parser.program

quoteEbpfPrograms :: String -> TH.ExpQ
quoteEbpfPrograms s = do
  loc <- location'
  prog <- parseProgram loc s
  THS.liftData prog
