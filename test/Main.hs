
import Test.Tasty
import qualified AsmParserTest as Parser
import qualified QuoteTest as Quote
import qualified EbpfTest as Ebpf


main = defaultMain $
  testGroup "All tests" [ Parser.test_basic
                        , Quote.test_basic
                        , Ebpf.test_roundtrips
                        ]
