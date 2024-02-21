{-# LANGUAGE LambdaCase, DeriveDataTypeable, NamedFieldPuns #-}
module Ebpf.Quote (
  ebpf,
  parseWithSpliceVars,
  SpliceVar(..)
) where

import Data.Data
import qualified Data.Generics as Gen
import qualified Language.Haskell.TH as TH
import Language.Haskell.TH.Quote
import qualified Language.Haskell.TH.Syntax as THS

import Ebpf.Asm
import qualified Ebpf.AsmParser as Parser
import Ebpf.AsmParser (SpliceConstructors(..))
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
  pos <- locToPos <$> TH.location
  prog <- eitherToQ $ parseWithSpliceVars (P.setPosition pos *> Parser.program) s
  THS.dataToExpQ (const Nothing `Gen.extQ` (qqSpliceVar :: Splicer RegImm)
                                `Gen.extQ` (qqSpliceVar :: Splicer Reg)
                                `Gen.extQ` (qqSpliceVar :: Splicer Imm)
                                `Gen.extQ` (qqSpliceVar :: Splicer HelperId)) prog
  where
    locToPos loc = uncurry (P.newPos (TH.loc_filename loc)) (TH.loc_start loc)
    eitherToQ = either (fail . show) return

data SpliceVar a = Var String | Concrete a
  deriving (Eq, Show, Data)

type Splicer a = SpliceVar a -> Maybe (TH.Q TH.Exp)

qqSpliceVar :: Data a => Splicer a
qqSpliceVar = \case
  Var v -> Just $ TH.varE (TH.mkName v)
  Concrete x -> Just $ THS.liftData x

parseWithSpliceVars :: Parser.Parser (SpliceConstructors (SpliceVar Reg)
                                                         (SpliceVar Imm)
                                                         (SpliceVar RegImm)
                                                         (SpliceVar HelperId)) a
                    -> String
                    -> Either P.ParseError a
parseWithSpliceVars parser str = P.runParser parser quotationCons "" str
  where
    S {onlyReg, onlyImm, rRegImm, iRegImm, iHelperId} = Parser.defaultSpliceCons
    quotationCons = S { onlyReg = Concrete . onlyReg
                      , varReg = Var
                      , onlyImm = Concrete . onlyImm
                      , varImm = Var
                      , iHelperId = Concrete . iHelperId
                      , vHelperId = Var
                      , vRegImm = Var
                      , rRegImm = Concrete . rRegImm
                      , iRegImm = Concrete . iRegImm
                      }
