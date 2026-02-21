# Project: whole-kernel-bitcode

Generate whole-kernel LLVM bitcode from a Linux kernel build tree.

## Architecture

Single-file tool (`kbitcode.py`) with four phases:
1. **Discovery** — index `compile_commands.json` by output object path
2. **Compilation** — recompile C sources to `.bc` with `-emit-llvm` (parallel)
3. **Hierarchy** — parse `.built-in.a.cmd` files for archive structure
4. **Linking** — `llvm-link` bitcode bottom-up, producing `built-in.bc`

## Key files

- `kbitcode.py` — all logic, CLI entry point
- `Dockerfile` — two-stage: kernel build (cached) + kbitcode runner
- `Makefile` — orchestration (`make build`, `make test`, `make shell`)
- `pyproject.toml` — no dependencies, Python 3.12+

## Development

```sh
uv run ruff check kbitcode.py
uv run ruff format kbitcode.py
```

## Testing

No unit tests. Integration test via Docker:

```sh
make build    # compiles kernel 6.12 with LLVM 18 inside container
make test     # runs kbitcode, output in ./output/built-in.bc
make shell    # interactive debugging
```

The Docker kernel build layer is cached — only kbitcode changes trigger a fast rebuild.

## Kernel .built-in.a.cmd format

Two variants exist:
- **With inputs:** `savedcmd_<path> := rm -f <out>;  printf "<dir>/%s " <in1> <in2> ... | xargs llvm-ar <flags> <out>`
- **Empty archive:** `savedcmd_<path> := rm -f <out>;  llvm-ar <flags> <out>` (no pipe, no inputs)

## Path resolution

`compile_commands.json` uses paths relative to the entry's `directory` field.
When kbitcode runs from a different directory than the build tree, all paths
must be resolved against `directory` before computing relative paths from
`build_dir`. This applies to both `discover_compile_commands` and
`compile_to_bitcode`.
