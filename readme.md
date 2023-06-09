# Whole Kernel Bitcode

Existing tools such as [wllvm](https://github.com/travitch/whole-program-llvm)
[gllvm](https://github.com/SRI-CSL/gllvm) don't seem to work without errors for
the linux kernel.

This is not an alternative to those tools. They work with not just the kernel
but any program. This is a tool specifically for the linux kernel. And hasn't
been tested on other programs.

## How it works

1. Compiles the kernel with llvm/clang.
2. Using the `compile_commands.json` generated by clang, it compiles each source
   file into a bitcode file.
3. Using the `.buit-in.a.cmd` files generated by the kernel build system, it
   hirarchically links the bitcode files into a single bitcode file.

Ceveats:

Certain source files in the kernel are assembly files. These files are not
linked into the final bitcode file.

## Notes

This has been tested on

- linux - 5.10.0
- defconfig
- llvm 10.0.1
