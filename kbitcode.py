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
from pathlib import Path

BUILTIN_ARCHIVE = "built-in.a"
BUILTIN_CMD = ".built-in.a.cmd"
BUILTIN_BC = "built-in.bc"
BUILTIN_BC_CMD = ".built-in.bc.cmd"

log = logging.getLogger("kbitcode")


# --- Discovery ---------------------------------------------------------------


def discover_compile_commands(
    build_dir: Path,
) -> dict[str, dict]:
    """Load compile_commands.json and index entries by output object path.

    Returns a dict mapping the *relative* .o path (relative to build_dir)
    to the full compile-command entry.
    """
    cc_path = build_dir / "compile_commands.json"
    if not cc_path.exists():
        sys.exit(f"compile_commands.json not found in {build_dir}")

    with open(cc_path) as f:
        entries = json.load(f)

    index: dict[str, dict] = {}
    for entry in entries:
        args = shlex.split(entry["command"])
        try:
            obj = args[args.index("-o") + 1]
        except (ValueError, IndexError):
            continue
        rel = os.path.relpath(obj, build_dir)
        index[rel] = entry

    log.info("Indexed %d compilation units from compile_commands.json", len(index))
    return index


def is_assembly_object(
    obj_rel: str,
    cc_index: dict[str, dict],
) -> bool:
    """Return True if an object file was produced from assembly (.S).

    An object is assembly if it has no entry in compile_commands.json or
    its source file ends with .S.
    """
    entry = cc_index.get(obj_rel)
    if entry is None:
        return True
    src = entry.get("file", "")
    return src.endswith(".S")


# --- Bitcode compilation -----------------------------------------------------


def compile_to_bitcode(
    entry: dict,
    build_dir: Path,
) -> tuple[str, bool, str]:
    """Recompile one C source to LLVM bitcode.

    Modifies the original clang invocation: adds -emit-llvm and changes
    the output extension from .o to .bc.

    Returns (bc_path_relative, success, message).
    """
    args = shlex.split(entry["command"])

    # Find output file position
    try:
        out_idx = args.index("-o") + 1
    except ValueError:
        return ("", False, "no -o flag in command")

    obj_path = args[out_idx]
    bc_path = obj_path.rsplit(".o", 1)[0] + ".bc"
    args[out_idx] = bc_path

    # Insert -emit-llvm before -c
    try:
        c_idx = args.index("-c")
        args.insert(c_idx, "-emit-llvm")
    except ValueError:
        return (bc_path, False, "no -c flag in command")

    # Use the directory from the entry if available
    cwd = entry.get("directory", str(build_dir))

    result = subprocess.run(
        args,
        cwd=cwd,
        capture_output=True,
        text=True,
    )

    bc_rel = os.path.relpath(bc_path, build_dir)
    if result.returncode != 0:
        return (bc_rel, False, result.stderr.strip())
    return (bc_rel, True, "")


def compile_all_bitcode(
    cc_index: dict[str, dict],
    build_dir: Path,
    jobs: int,
) -> set[str]:
    """Recompile all C sources to bitcode in parallel.

    Returns the set of relative .bc paths that were successfully compiled.
    """
    # Filter out assembly entries
    c_entries = [
        entry
        for rel, entry in cc_index.items()
        if not is_assembly_object(rel, cc_index)
    ]
    log.info("Compiling %d C files to bitcode (jobs=%d)", len(c_entries), jobs)

    compiled: set[str] = set()
    failed = 0

    with ProcessPoolExecutor(max_workers=jobs) as pool:
        futures = {
            pool.submit(compile_to_bitcode, entry, build_dir): entry
            for entry in c_entries
        }
        for future in as_completed(futures):
            bc_rel, ok, msg = future.result()
            if ok:
                compiled.add(bc_rel)
            else:
                failed += 1
                log.warning("Failed to compile %s: %s", bc_rel, msg)

    log.info(
        "Bitcode compilation: %d succeeded, %d failed",
        len(compiled),
        failed,
    )
    return compiled


# --- Hierarchy discovery ------------------------------------------------------


def discover_builtin_hierarchy(
    build_dir: Path,
) -> list[tuple[str, list[str]]]:
    """Parse .built-in.a.cmd files into a linking plan.

    Each .built-in.a.cmd contains an llvm-ar command that archives .o and
    .a files into a built-in.a.  We extract the output and input paths.

    Returns a list of (output_rel, [input_rels]) sorted deepest-first so
    leaf archives are linked before their parents.
    """
    cmd_files = sorted(build_dir.glob("**/" + BUILTIN_CMD))
    hierarchy: list[tuple[str, list[str]]] = []

    for cmd_file in cmd_files:
        text = cmd_file.read_text().strip()
        # Format: "cmd_<path> := <cmd>; llvm-ar <flags> <out> <in...>"
        # The llvm-ar invocation follows the semicolon.
        parts = text.split(";")
        if len(parts) < 2:
            log.warning("Unexpected format in %s, skipping", cmd_file)
            continue

        ar_cmd = parts[1].strip()
        if not ar_cmd.startswith("llvm-ar"):
            log.warning("No llvm-ar found in %s, skipping", cmd_file)
            continue

        tokens = ar_cmd.split()
        # tokens: [llvm-ar, flags, outfile, infile1, infile2, ...]
        if len(tokens) < 3:
            log.warning("Incomplete llvm-ar command in %s", cmd_file)
            continue

        outfile = tokens[2]
        infiles = tokens[3:]

        out_rel = os.path.relpath(outfile, build_dir)
        in_rels = [os.path.relpath(f, build_dir) for f in infiles]
        hierarchy.append((out_rel, in_rels))

    # Sort deepest first (most path separators = deepest)
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
        # Fallback: write an empty file (llvm-link can handle it)
        path.write_bytes(b"")


def link_bitcode_hierarchy(
    hierarchy: list[tuple[str, list[str]]],
    build_dir: Path,
    output_dir: Path,
    cc_index: dict[str, dict],
) -> None:
    """Link bitcode files following the kernel's archive hierarchy.

    For each .built-in.a.cmd entry (deepest-first):
    - Map .o inputs to .bc, .a inputs to their linked .bc
    - Skip assembly objects
    - Run llvm-link to produce the archive-level .bc
    """
    assembly_objects: set[str] = set()
    for obj_rel in cc_index:
        if is_assembly_object(obj_rel, cc_index):
            assembly_objects.add(obj_rel)

    # Also track .o files that have no compile_commands entry at all
    all_cc_objects = set(cc_index.keys())

    for out_rel, in_rels in hierarchy:
        # Output: built-in.a → built-in.bc
        out_bc_rel = out_rel.rsplit(".a", 1)[0] + ".bc"
        out_bc = output_dir / out_bc_rel
        out_bc.parent.mkdir(parents=True, exist_ok=True)

        bc_inputs: list[Path] = []
        for in_rel in in_rels:
            if in_rel.endswith(".o"):
                # Check if this is an assembly object
                if in_rel in assembly_objects or in_rel not in all_cc_objects:
                    log.debug("Skipping assembly object: %s", in_rel)
                    continue
                # .o → .bc
                bc_rel = in_rel.rsplit(".o", 1)[0] + ".bc"
                bc_path = build_dir / bc_rel
                if bc_path.exists():
                    bc_inputs.append(bc_path)
                else:
                    log.debug("Missing bitcode for %s, skipping", in_rel)

            elif in_rel.endswith(".a"):
                # .a → .bc (already linked in a previous iteration)
                bc_rel = in_rel.rsplit(".a", 1)[0] + ".bc"
                bc_path = output_dir / bc_rel
                if bc_path.exists():
                    bc_inputs.append(bc_path)
                else:
                    log.debug("Missing linked bitcode for %s", in_rel)

        if not bc_inputs:
            _make_empty_bc(out_bc)
            _write_bc_cmd(out_bc.parent, output_dir, "# empty — no C inputs")
            continue

        cmd = [
            "llvm-link",
            "-o",
            str(out_bc),
            *[str(p) for p in bc_inputs],
        ]

        _write_bc_cmd(out_bc.parent, output_dir, " ".join(cmd))

        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            log.error(
                "llvm-link failed for %s: %s",
                out_bc_rel,
                result.stderr.strip(),
            )
            _make_empty_bc(out_bc)


def _write_bc_cmd(
    directory: Path,
    output_dir: Path,
    cmd: str,
) -> None:
    """Write a .built-in.bc.cmd file alongside the linked bitcode."""
    cmd_file = directory / BUILTIN_BC_CMD
    cmd_file.write_text(cmd + "\n")


def link_final_bitcode(output_dir: Path) -> Path:
    """Link top-level built-in.bc files into one whole-kernel bitcode."""
    top_level = sorted(output_dir.glob(f"*/{BUILTIN_BC}"))
    if not top_level:
        sys.exit("No top-level built-in.bc files found to link")

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
        sys.exit(f"Final llvm-link failed: {result.stderr.strip()}")

    log.info("Whole-kernel bitcode: %s", final)
    return final


# --- CLI ----------------------------------------------------------------------


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Generate whole-kernel LLVM bitcode from a kernel build tree.",
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

    # 1. Discover compilation commands
    cc_index = discover_compile_commands(build_dir)

    # 2. Compile all C sources to bitcode
    compile_all_bitcode(cc_index, build_dir, args.jobs)

    # 3. Discover archive hierarchy
    hierarchy = discover_builtin_hierarchy(build_dir)

    # 4. Link bitcode following the hierarchy
    link_bitcode_hierarchy(hierarchy, build_dir, output_dir, cc_index)

    # 5. Final top-level link
    final = link_final_bitcode(output_dir)
    log.info("Done. Output: %s", final)


if __name__ == "__main__":
    main()
