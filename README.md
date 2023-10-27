eBPF Tools
==========

Framework for allowing easy experimentation with eBPF byte-code.

The project can be used both as a library for working with eBPF
byte-code, and it comes with a command-line program that can be as an
assembler and (eventually) a disassembler.


Build instructions
------------------

Build with:

    $ cabal build


As a library
------------

The project consists of a number of modules:

 * [`Ebpf.Asm`](./src/Ebpf/Asm.hs) types for representing AST for eBPF programs.
 * [`Ebpf.AsmParser`](./src/Ebpf/AsmParser.hs) parser for a textual format of eBPF bytecode.
 * [`Ebpf.Decode`](./src/Ebpf/Decode.hs) reading bytecode into an AST (incomplete).
 * [`Ebpf.Encode`](./src/Ebpf/Encode.hs) encoding the AST to bytecode.
 * [`Ebpf.Helpers`](./src/Ebpf/Helpers.hs) helper functions for building AST.
 * [`Ebpf.Display`](./src/Ebpf/Display.hs) for user-facing printing of the AST.



Command-line executable
-----------------------

```
$ cabal exec -- ebpf-tools --help
Usage: ebpf-tools ((-a|--assemble) | (-d|--disassemble) | --dump)
                  [-o|--output OUTFILE] INFILE

  Assembler and disassembler for eBPF bytecode

Available options:
  -a,--assemble            Parse asm file and write bytecode to output
  -d,--disassemble         Parse bytecode file and write assembly to output
  --dump                   Parse asm file and print an AST
  -o,--output OUTFILE      Write output to OUTFILE (writes to stdout if not
                           given)
  -h,--help                Show this help text
```


eBPF Resources
--------------

See

* <https://ebpf.io>

* [Linux documentation for the eBPF instruction
  set](https://www.kernel.org/doc/Documentation/networking/filter.txt)

* [Instruction set
  reference](https://github.com/iovisor/bpf-docs/blob/master/eBPF.md)

* [ubpf: User-space eBPF VM](https://github.com/iovisor/ubpf/)
