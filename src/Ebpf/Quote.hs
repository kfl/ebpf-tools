module Ebpf.Quote (ebpf) where

import qualified Language.Haskell.TH as TH
import qualified Language.Haskell.TH.Syntax as THS
import Language.Haskell.TH.Quote

import qualified Ebpf.Asm as A
import qualified Ebpf.AsmParser as Parser
import qualified Text.Parsec as P

ebpf  :: QuasiQuoter
ebpf  =  QuasiQuoter { quoteExp = quoteEbpfPrograms
                     , quotePat = error "Not allowed in patterns"
                     , quoteType = error "Not allowed in types"
                     , quoteDec  = error "Not allowed in declarations"
                     }


parseProgram :: MonadFail m => (String, Int, Int) -> String -> m A.Program
parseProgram (file, line, col) s =
    case P.parse positionProgram file s of
      Left err   -> fail $ show err
      Right prog -> return prog
  where
    positionProgram :: P.Parsec String () [A.Instruction]
    positionProgram = do
      pos <- P.getPosition
      P.setPosition $
        (flip P.setSourceName) file $
        (flip P.setSourceLine) line $
        (flip P.setSourceColumn) col $
        pos
      prog <- Parser.program
      return prog

quoteEbpfPrograms :: String -> TH.ExpQ
quoteEbpfPrograms s = do
  loc <- TH.location
  let pos =  (TH.loc_filename loc,
              fst (TH.loc_start loc),
              snd (TH.loc_start loc))
  prog <- parseProgram pos s
  THS.liftData prog
