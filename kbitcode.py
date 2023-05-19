#!/usr/bin/env python3

import json
import os
from pathlib import Path
from typing import List

kernel_build_folder = Path("./outputs/kbuild/v5.10-defconfig/kernel")
assert kernel_build_folder.exists()

kernel_bitcode_folder = Path("./outputs/kbitcode/v5.10-defconfig/bitcode")
kernel_bitcode_folder.mkdir(parents=True, exist_ok=True)

BUILTIN_FILE = "built-in.a"
BUILTIN_FILE_BC = "built-in.bc"

BUILTIN_CMD_FILE = ".built-in.a.cmd"
BUILTIN_CMD_FILE_BC = ".built-in.bc.cmd"


# these files do not exist in the kernel build folder
# the object files are produced from assembly files (.S)
# so no bitcode files are produced
skip_bitcode_files = [
    Path(i)
    for i in [
        "arch/x86/entry/entry_64_compat.bc",
        "arch/x86/entry/entry_64.bc",
        "arch/x86/entry/thunk_64.bc",
        "arch/x86/entry/vsyscall/vsyscall_emu_64.bc",
        "arch/x86/kernel/acpi/wakeup_64.bc",
        "arch/x86/kernel/irqflags.bc",
        "arch/x86/kernel/relocate_kernel_64.bc",
        "arch/x86/lib/hweight.bc",
        "arch/x86/lib/iomap_copy_64.bc",
        "arch/x86/lib/msr-reg.bc",
        "arch/x86/platform/efi/efi_stub_64.bc",
        "arch/x86/platform/efi/efi_thunk_64.bc",
        "arch/x86/power/hibernate_asm_64.bc",
        "arch/x86/realmode/rmpiggy.bc",
        "certs/system_certificates.bc",
        "usr/initramfs_data.bc",
    ]
]


def make_compile_commands():
    # make compile_commands.json
    cmd = f"cd {kernel_build_folder} && scripts/clang-tools/gen_compile_commands.py -d {kernel_build_folder} -o {kernel_build_folder}/compile_commands.json"
    os.system()


def make_bitcode():
    compile_commads = kernel_build_folder / "compile_commands.json"
    assert compile_commads.exists()

    with open(compile_commads, "r") as f:
        compile_commands = json.load(f)

        for unit in compile_commands:
            file = unit["file"]
            cmd = unit["command"]
            cmd = cmd.replace("-c ", "-emit-llvm -c ")
            x = cmd.split()
            obj_file = x[x.index("-o") + 1]
            bc_file = obj_file.replace(".o", ".bc")
            cmd = cmd.replace(obj_file, bc_file)
            if "/outputs/" in file:
                src_file = x[-1]
                cmd = cmd.replace(src_file, file)
            os.system(cmd)


def copy_to_bitcode_folder(src_file: Path):
    try:
        assert src_file.exists()
    except:
        if src_file.relative_to(kernel_build_folder) in skip_bitcode_files:
            print(f"Skipping {src_file}")
            return
        else:
            print(f"Could not find {src_file}")
            raise

    dest_file = kernel_bitcode_folder / src_file.relative_to(kernel_build_folder)
    dest_file.parent.mkdir(parents=True, exist_ok=True)
    if not dest_file.exists():
        dest_file.write_bytes(src_file.read_bytes())
        assert dest_file.exists()


def builtin_to_cmd(builtin_file_path: Path):
    assert builtin_file_path.exists()
    command = builtin_file_path.read_text()
    llvm_ar = command.split(";")[1].strip()
    assert llvm_ar.startswith("llvm-ar")

    llvm_ar = llvm_ar.split()
    ar, flags, outfile, infiles = llvm_ar[0], llvm_ar[1], llvm_ar[2], llvm_ar[3:]
    assert outfile.endswith("built-in.a")
    assert all([file.endswith(".o") or file.endswith(".a") for file in infiles])

    return ar, flags, outfile, infiles


def copy_build_files(builtin_files: List[Path]):
    for builtin_file in builtin_files:
        copy_to_bitcode_folder(builtin_file)
        _, _, outfile, infiles = builtin_to_cmd(builtin_file)

        for infile in infiles:
            # copy every input to kernel_bitcode_folder
            copy_to_bitcode_folder(kernel_build_folder / infile)

            # copy corresponding bitcode to kernel_bitcode_folder
            if infile.endswith(".o"):
                bitcode_file = kernel_build_folder / infile.replace(".o", ".bc")
                copy_to_bitcode_folder(bitcode_file)


def create_dummy_file(file: Path):
    print(f" creating a dummy file {file}")
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_bytes(b"")
    assert file.exists()


def write_builtin_bc_cmd(path: Path, cmd: str):
    builtin_bc_cmd_file = path / BUILTIN_CMD_FILE_BC
    if cmd == "dummy":
        builtin_bc_cmd_file = path / BUILTIN_CMD_FILE_BC
        builtin_bc_cmd_file = builtin_bc_cmd_file.with_suffix(".dummy")
        builtin_bc_cmd_file.write_text("")
    else:
        builtin_bc_cmd_file.write_text(cmd)

    assert builtin_bc_cmd_file.exists()


def build_linked_bitcode(builtin_files: List[Path]):
    # sort by length of path, deeper paths first
    builtin_files = sorted(builtin_files, key=lambda x: str(x).count("/"), reverse=True)
    builtin_files = sorted(builtin_files, key=lambda x: x, reverse=True)

    for builtin_file in builtin_files:
        _, _, outfile, infiles = builtin_to_cmd(builtin_file)

        infiles = [kernel_bitcode_folder / infile for infile in infiles]
        infiles = [infile.with_suffix(".bc") for infile in infiles]
        outfile = kernel_bitcode_folder / outfile
        outfile = outfile.with_suffix(".bc")

        if outfile.exists():
            continue

        for infile in infiles:
            if not infile.exists() and infile.name.startswith("built-in"):
                # create a dummy built-in.bc in file
                write_builtin_bc_cmd(infile.parent, "dummy")
                create_dummy_file(infile)
            else:
                try:
                    assert infile.exists()
                except:
                    if infile.relative_to(kernel_bitcode_folder) in skip_bitcode_files:
                        create_dummy_file(infile)
                    else:
                        raise

        if len(infiles) == 0:
            # create a dummy out file
            create_dummy_file(outfile)
            write_builtin_bc_cmd(outfile.parent, "dummy")
            continue

        # link bitcode files
        linker = "llvm-link"
        flags = "-o"
        cmd = f'{linker} {flags} {outfile} {" ".join([str(i) for i in infiles])}'
        write_builtin_bc_cmd(outfile.parent, cmd)

        try:
            assert os.system(cmd) == 0
        except:
            import code

            code.interact(local={**globals(), **locals()})

    print("Done building linked bitcode files")


def remove_linked_bitcode(builtin_files: List[Path]):
    # sort by length of path, deeper paths first
    builtin_files = sorted(builtin_files, key=lambda x: str(x).count("/"), reverse=True)
    builtin_files = sorted(builtin_files, key=lambda x: x, reverse=True)

    for builtin_file in builtin_files:
        _, _, outfile, infiles = builtin_to_cmd(builtin_file)

        outfile = kernel_bitcode_folder / outfile.replace(".a", ".bc")
        assert outfile.name.startswith("built-in")

        if outfile.exists():
            outfile.unlink()
        else:
            print(f" {outfile} does not exist")

    print("Done removing linked bitcode files")


def build_full_bitcode():
    infiles = list(kernel_bitcode_folder.glob(f"*/{BUILTIN_FILE_BC}"))
    assert len(infiles) > 0

    outfile = kernel_bitcode_folder / "built-in.bc"
    if not outfile.exists():
        cmd = f'llvm-link -o {outfile} {" ".join([str(i) for i in infiles])}'
        assert os.system(cmd) == 0

    print("Done building full bitcode file")


def main():
    # make_compile_commands()
    # make_bitcode()

    build_builtin_files = list(kernel_build_folder.glob("**/" + BUILTIN_CMD_FILE))
    print(
        "total built-in.a.cmd files in kernel build folder:", len(build_builtin_files)
    )

    copy_build_files(build_builtin_files)

    bitcode_builtin_files = list(kernel_bitcode_folder.glob("**/" + BUILTIN_CMD_FILE))
    print(
        "total built-in.a.cmd files in kernel bitcode folder:",
        len(bitcode_builtin_files),
    )
    assert len(build_builtin_files) == len(bitcode_builtin_files)

    remove_linked_bitcode(bitcode_builtin_files)
    build_linked_bitcode(bitcode_builtin_files)
    build_full_bitcode()


if __name__ == "__main__":
    main()
