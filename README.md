# Whole Kernel Bitcode

Generate whole-kernel LLVM bitcode from a Linux kernel build tree.

Existing tools like [wllvm](https://github.com/travitch/whole-program-llvm) and
[gllvm](https://github.com/SRI-CSL/gllvm) don't work reliably for the Linux
kernel. This tool is purpose-built for the kernel's build system and has not been
tested on other programs.

## How it works

1. Reads `compile_commands.json` from a kernel built with `make LLVM=1`.
2. Recompiles each C source to LLVM bitcode (`-emit-llvm`) in parallel.
3. Parses `.built-in.a.cmd` files to reconstruct the kernel's archive hierarchy.
4. Links bitcode bottom-up using `llvm-link`, producing a single `built-in.bc`.

Assembly (`.S`) files are skipped — they have no bitcode representation.

## Requirements

- Linux kernel source built with `make LLVM=1` (produces `compile_commands.json`
  and `.built-in.a.cmd` files)
- LLVM toolchain (`clang`, `llvm-link`, `llvm-as`)
- Python 3.12+

## Usage

### Direct

```sh
# Build the kernel with LLVM
cd /path/to/linux
make LLVM=1 defconfig
make LLVM=1 -j$(nproc)
python3 scripts/clang-tools/gen_compile_commands.py

# Generate whole-kernel bitcode
uv run kbitcode --build-dir /path/to/linux --output-dir ./output -v
```

### Docker (no local toolchain needed)

The included Dockerfile builds a kernel and runs kbitcode in a container.

```sh
make build                           # build image (compiles kernel 6.12 LTS)
make test                            # run kbitcode, output in ./output/
make shell                           # interactive shell for debugging
KERNEL_VERSION=6.13.1 make build     # use a different kernel version
KERNEL_CONFIG=allmodconfig make build # use a different kernel config
```

## CLI options

```
--build-dir DIR    Path to kernel build output (must contain compile_commands.json)
--output-dir DIR   Path for bitcode output
-j, --jobs N       Parallel compilation jobs (default: cpu count)
-v, --verbose      Enable debug logging
```

## Tested on

- Linux 6.12.14, defconfig, LLVM 18 (arm64)
- Linux 5.10.0, defconfig, LLVM 10.0.1
