{-# LANGUAGE LambdaCase, DeriveDataTypeable #-}
module Ebpf.Quote (ebpf) where

import qualified Language.Haskell.TH as TH
import qualified Language.Haskell.TH.Syntax as THS
import Language.Haskell.TH.Quote
import qualified Data.Generics as Gen
import Data.Data

import Ebpf.Asm
import qualified Ebpf.AsmParser as Parser
import qualified Text.Parsec as P
import qualified Text.Parsec.Pos as P

ebpf :: QuasiQuoter
ebpf = QuasiQuoter { quoteExp = quoteEbpfPrograms
                   , quotePat = error "Not allowed in patterns"
                   , quoteType = error "Not allowed in types"
                   , quoteDec  = error "Not allowed in declarations"
                   }

quoteEbpfPrograms :: String -> TH.ExpQ
quoteEbpfPrograms s = do
  loc <- location'
  prog <- parseProgram loc s
  THS.dataToExpQ (const Nothing `Gen.extQ` (qqSpliceVar :: Splicer RegImm)) prog

location' :: TH.Q P.SourcePos
location' = aux <$> TH.location
  where
    aux loc = uncurry (P.newPos (TH.loc_filename loc)) (TH.loc_start loc)

data SpliceVar a = Var String | Concrete a
  deriving (Eq, Show, Data)

type Splicer a = SpliceVar a -> Maybe (TH.Q TH.Exp)

qqSpliceVar :: Data a => Splicer a
qqSpliceVar = \case
  Var v -> Just $ TH.varE (TH.mkName v)
  Concrete x -> Just $ THS.liftData x

--parseProgram :: MonadFail m => P.SourcePos -> String -> m [Inst Reg Imm (SpliceVar RegImm)]
parseProgram pos s =
  case P.runParser positionedProgram quotationCons (P.sourceName pos) s of
    Left err   -> fail $ show err
    Right prog -> return prog
  where
    positionedProgram = P.setPosition pos *> Parser.program
    (_, reg, imm) = Parser.defaultCons
    quotationCons = (Var, Concrete . reg, Concrete . imm)
