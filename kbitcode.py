#!/usr/bin/env python3
"""Generate whole-kernel LLVM bitcode from a kernel build tree.

Uses compile_commands.json for compilation commands and .built-in.a.cmd
files for the archive hierarchy — both produced by `make LLVM=1`.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shlex
import subprocess
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

BUILTIN_ARCHIVE = "built-in.a"
BUILTIN_CMD = ".built-in.a.cmd"
BUILTIN_BC = "built-in.bc"
BUILTIN_BC_CMD = ".built-in.bc.cmd"

log = logging.getLogger("kbitcode")

CompileIndex = dict[str, dict]
ArchiveEntry = tuple[str, list[str]]


class KbitcodeError(Exception):
    """Raised for fatal errors during bitcode generation."""


def _resolve_rel(
    raw: str,
    base_dir: str,
    build_dir: Path,
) -> str:
    """Resolve a possibly-relative path against base_dir, then
    return the result relative to build_dir.
    """
    abs_path = raw if os.path.isabs(raw) else os.path.join(base_dir, raw)
    return os.path.relpath(abs_path, build_dir)


def _to_bc(path: str, old_ext: str = ".o") -> str:
    """Replace a trailing extension with .bc."""
    return path.rsplit(old_ext, 1)[0] + ".bc"


# --- Discovery ---------------------------------------------------------------


def discover_compile_commands(build_dir: Path) -> CompileIndex:
    """Load compile_commands.json and index entries by output object
    path (relative to build_dir).
    """
    cc_path = build_dir / "compile_commands.json"
    if not cc_path.exists():
        raise KbitcodeError(f"compile_commands.json not found in {build_dir}")

    entries = json.loads(cc_path.read_text())

    index: CompileIndex = {}
    for entry in entries:
        args = shlex.split(entry["command"])
        try:
            obj = args[args.index("-o") + 1]
        except (ValueError, IndexError):
            continue
        directory = entry.get("directory", str(build_dir))
        index[_resolve_rel(obj, directory, build_dir)] = entry

    log.info(
        "Indexed %d compilation units from compile_commands.json",
        len(index),
    )
    return index


def _is_assembly_object(
    obj_rel: str,
    cc_index: CompileIndex,
) -> bool:
    """True if an object was assembled from .S (no bitcode possible)."""
    entry = cc_index.get(obj_rel)
    if entry is None:
        return True
    return entry.get("file", "").endswith(".S")


# --- Bitcode compilation -----------------------------------------------------


@dataclass(frozen=True, slots=True)
class CompileResult:
    """Outcome of compiling a single C source to bitcode."""

    bc_rel: str
    ok: bool
    message: str


def _compile_one(
    entry: dict,
    build_dir: Path,
) -> CompileResult:
    """Recompile one C source to LLVM bitcode.

    Adds -emit-llvm and swaps the output extension from .o to .bc.
    """
    args = shlex.split(entry["command"])

    try:
        out_idx = args.index("-o") + 1
    except ValueError:
        return CompileResult("", False, "no -o flag in command")

    obj_path = args[out_idx]
    bc_path = _to_bc(obj_path)
    args[out_idx] = bc_path

    try:
        c_idx = args.index("-c")
        args.insert(c_idx, "-emit-llvm")
    except ValueError:
        return CompileResult(bc_path, False, "no -c flag in command")

    cwd = entry.get("directory", str(build_dir))
    result = subprocess.run(
        args,
        cwd=cwd,
        capture_output=True,
        text=True,
    )

    bc_rel = _resolve_rel(bc_path, cwd, build_dir)
    if result.returncode != 0:
        return CompileResult(bc_rel, False, result.stderr.strip())
    return CompileResult(bc_rel, True, "")


def compile_all_bitcode(
    cc_index: CompileIndex,
    build_dir: Path,
    jobs: int,
) -> set[str]:
    """Recompile all C sources to bitcode in parallel.

    Returns the set of relative .bc paths that compiled successfully.
    """
    c_entries = [
        entry
        for rel, entry in cc_index.items()
        if not _is_assembly_object(rel, cc_index)
    ]
    log.info(
        "Compiling %d C files to bitcode (jobs=%d)",
        len(c_entries),
        jobs,
    )

    compiled: set[str] = set()
    failed = 0

    with ProcessPoolExecutor(max_workers=jobs) as pool:
        futures = {
            pool.submit(_compile_one, entry, build_dir): entry for entry in c_entries
        }
        for future in as_completed(futures):
            r = future.result()
            if r.ok:
                compiled.add(r.bc_rel)
            else:
                failed += 1
                log.warning(
                    "Failed to compile %s: %s",
                    r.bc_rel,
                    r.message,
                )

    log.info(
        "Bitcode compilation: %d succeeded, %d failed",
        len(compiled),
        failed,
    )
    return compiled


# --- Hierarchy discovery ------------------------------------------------------


def _parse_builtin_cmd(
    cmd_file: Path,
    build_dir: Path,
) -> ArchiveEntry | None:
    """Parse a single .built-in.a.cmd file into (output_rel, [input_rels]).

    Returns None if the file can't be parsed.
    """
    text = cmd_file.read_text().strip()

    if ":=" not in text:
        log.warning("Unexpected format in %s, skipping", cmd_file)
        return None

    cmd_part = text.split(":=", 1)[1].strip()

    # Extract output archive from "rm -f <outfile>;" prefix
    parts = cmd_part.split(";", 1)
    rm_tokens = parts[0].strip().split()
    if len(rm_tokens) < 3 or rm_tokens[0] != "rm":
        log.warning("No 'rm -f' prefix in %s, skipping", cmd_file)
        return None

    outfile = rm_tokens[-1]

    if len(parts) < 2:
        log.warning("No command after rm in %s, skipping", cmd_file)
        return None

    rest = parts[1].strip()

    # Inputs come from: printf "<dir>/%s " <in1> ... | xargs llvm-ar ...
    pipe_idx = rest.find("|")
    if pipe_idx == -1:
        # Empty archive (no inputs) — still valid
        log.debug("No pipe in %s, treating as empty archive", cmd_file)
        out_rel = _resolve_rel(outfile, str(build_dir), build_dir)
        return (out_rel, [])

    printf_tokens = rest[:pipe_idx].strip().split()
    if len(printf_tokens) < 3 or printf_tokens[0] != "printf":
        log.warning("No printf found in %s, skipping", cmd_file)
        return None

    fmt_str = printf_tokens[1].strip('"').strip("'")
    raw_inputs = printf_tokens[2:]
    infiles = [fmt_str.replace("%s", inp) for inp in raw_inputs]

    out_rel = _resolve_rel(outfile, str(build_dir), build_dir)
    in_rels = [_resolve_rel(f, str(build_dir), build_dir) for f in infiles]
    return (out_rel, in_rels)


def discover_builtin_hierarchy(
    build_dir: Path,
) -> list[ArchiveEntry]:
    """Parse all .built-in.a.cmd files into a linking plan.

    Returns entries sorted deepest-first so leaf archives are linked
    before their parents.
    """
    cmd_files = sorted(build_dir.glob("**/" + BUILTIN_CMD))
    hierarchy: list[ArchiveEntry] = []

    for cmd_file in cmd_files:
        entry = _parse_builtin_cmd(cmd_file, build_dir)
        if entry is not None:
            hierarchy.append(entry)

    hierarchy.sort(key=lambda x: x[0].count("/"), reverse=True)
    log.info("Discovered %d .built-in.a.cmd entries", len(hierarchy))
    return hierarchy


# --- Bitcode linking ----------------------------------------------------------


def _make_empty_bc(path: Path) -> None:
    """Create a minimal empty LLVM bitcode file using llvm-as."""
    result = subprocess.run(
        ["llvm-as", "-o", str(path)],
        input="",
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        path.write_bytes(b"")


def _write_bc_cmd(directory: Path, cmd: str) -> None:
    """Write a .built-in.bc.cmd file alongside the linked bitcode."""
    (directory / BUILTIN_BC_CMD).write_text(cmd + "\n")


def _collect_bc_inputs(
    in_rels: list[str],
    build_dir: Path,
    output_dir: Path,
    assembly_objects: set[str],
    all_cc_objects: set[str],
) -> list[Path]:
    """Resolve input .o/.a paths to their .bc counterparts."""
    bc_inputs: list[Path] = []

    for in_rel in in_rels:
        if in_rel.endswith(".o"):
            if in_rel in assembly_objects or in_rel not in all_cc_objects:
                log.debug("Skipping assembly object: %s", in_rel)
                continue
            bc_path = build_dir / _to_bc(in_rel)
            if bc_path.exists():
                bc_inputs.append(bc_path)
            else:
                log.debug("Missing bitcode for %s, skipping", in_rel)

        elif in_rel.endswith(".a"):
            bc_path = output_dir / _to_bc(in_rel, ".a")
            if bc_path.exists():
                bc_inputs.append(bc_path)
            else:
                log.debug("Missing linked bitcode for %s", in_rel)

    return bc_inputs


def link_bitcode_hierarchy(
    hierarchy: list[ArchiveEntry],
    build_dir: Path,
    output_dir: Path,
    cc_index: CompileIndex,
) -> None:
    """Link bitcode files following the kernel's archive hierarchy.

    For each entry (deepest-first): map .o→.bc and .a→linked .bc,
    skip assembly objects, run llvm-link.
    """
    assembly_objects = {rel for rel in cc_index if _is_assembly_object(rel, cc_index)}
    all_cc_objects = set(cc_index.keys())

    for out_rel, in_rels in hierarchy:
        out_bc_rel = _to_bc(out_rel, ".a")
        out_bc = output_dir / out_bc_rel
        out_bc.parent.mkdir(parents=True, exist_ok=True)

        bc_inputs = _collect_bc_inputs(
            in_rels,
            build_dir,
            output_dir,
            assembly_objects,
            all_cc_objects,
        )

        if not bc_inputs:
            _make_empty_bc(out_bc)
            _write_bc_cmd(out_bc.parent, "# empty — no C inputs")
            continue

        cmd = [
            "llvm-link",
            "-o",
            str(out_bc),
            *[str(p) for p in bc_inputs],
        ]
        _write_bc_cmd(out_bc.parent, " ".join(cmd))

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            log.error(
                "llvm-link failed for %s: %s",
                out_bc_rel,
                result.stderr.strip(),
            )
            _make_empty_bc(out_bc)


def link_final_bitcode(output_dir: Path) -> Path:
    """Link top-level built-in.bc files into one whole-kernel bitcode."""
    top_level = sorted(output_dir.glob(f"*/{BUILTIN_BC}"))
    if not top_level:
        raise KbitcodeError("No top-level built-in.bc files found to link")

    final = output_dir / BUILTIN_BC
    cmd = [
        "llvm-link",
        "-o",
        str(final),
        *[str(p) for p in top_level],
    ]

    log.info(
        "Linking %d top-level archives into %s",
        len(top_level),
        final,
    )
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise KbitcodeError(f"Final llvm-link failed: {result.stderr.strip()}")

    log.info("Whole-kernel bitcode: %s", final)
    return final


# --- CLI ----------------------------------------------------------------------


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=("Generate whole-kernel LLVM bitcode from a kernel build tree."),
    )
    parser.add_argument(
        "--build-dir",
        type=Path,
        required=True,
        help="Path to kernel build output (must contain compile_commands.json)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Path for bitcode output",
    )
    parser.add_argument(
        "-j",
        "--jobs",
        type=int,
        default=os.cpu_count() or 1,
        help="Parallel jobs for compilation (default: cpu count)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    """Entry point: orchestrate bitcode generation."""
    args = parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    build_dir = args.build_dir.resolve()
    output_dir = args.output_dir.resolve()

    if not build_dir.is_dir():
        sys.exit(f"Build directory does not exist: {build_dir}")

    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        cc_index = discover_compile_commands(build_dir)
        compile_all_bitcode(cc_index, build_dir, args.jobs)
        hierarchy = discover_builtin_hierarchy(build_dir)
        link_bitcode_hierarchy(
            hierarchy,
            build_dir,
            output_dir,
            cc_index,
        )
        final = link_final_bitcode(output_dir)
    except KbitcodeError as exc:
        sys.exit(str(exc))

    log.info("Done. Output: %s", final)


if __name__ == "__main__":
    main()
