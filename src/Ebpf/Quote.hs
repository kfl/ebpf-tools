{-# LANGUAGE LambdaCase, DeriveDataTypeable, NamedFieldPuns #-}
module Ebpf.Quote (ebpf) where

import qualified Language.Haskell.TH as TH
import qualified Language.Haskell.TH.Syntax as THS
import Language.Haskell.TH.Quote
import qualified Data.Generics as Gen
import Data.Data

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
  prog <- parseWithSpliceVars (P.setPosition pos *> Parser.program) s
  THS.dataToExpQ (const Nothing `Gen.extQ` (qqSpliceVar :: Splicer RegImm)
                                `Gen.extQ` (qqSpliceVar :: Splicer Reg)
                                `Gen.extQ` (qqSpliceVar :: Splicer Imm)) prog
  where
    locToPos loc = uncurry (P.newPos (TH.loc_filename loc)) (TH.loc_start loc)

data SpliceVar a = Var String | Concrete a
  deriving (Eq, Show, Data)

type Splicer a = SpliceVar a -> Maybe (TH.Q TH.Exp)

qqSpliceVar :: Data a => Splicer a
qqSpliceVar = \case
  Var v -> Just $ TH.varE (TH.mkName v)
  Concrete x -> Just $ THS.liftData x

parseWithSpliceVars :: MonadFail m =>
                       Parser.Parser (SpliceConstructors (SpliceVar Reg)
                                                         (SpliceVar Imm)
                                                         (SpliceVar RegImm)) a
                    -> String
                    -> m a
parseWithSpliceVars parser str =
  either (fail . show) return $ P.runParser parser quotationCons "" str
  where
    S {onlyReg, onlyImm, rRegImm, iRegImm} = Parser.defaultSpliceCons
    quotationCons = S { onlyReg = Concrete . onlyReg
                      , varReg = Var
                      , onlyImm = Concrete . onlyImm
                      , varImm = Var
                      , vRegImm = Var
                      , rRegImm = Concrete . rRegImm
                      , iRegImm = Concrete . iRegImm
                      }
