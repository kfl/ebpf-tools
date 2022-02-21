eBPF Tools
==========

Framework for allowing easy experimentation with eBPF byte-code.

Build instructions
------------------

Build with:

    $ cabal build

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
