
import Test.Tasty
import qualified AsmParserTest as Parser
import qualified EbpfTest as Ebpf


main = defaultMain $
  testGroup "All tests" [ Parser.test_basic
                        , Ebpf.test_parse_display
                        , Ebpf.test_decode_encode
                        ]
