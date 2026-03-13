#!/usr/bin/env python3
"""Test ChaCha20 block function against RFC 8439 Section 2.3.2 test vector."""

import subprocess
import struct
import os
import sys
import re


# RFC 8439 Section 2.3.2 expected output state (16 LE uint32)
EXPECTED_STATE = [
    0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
    0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3,
    0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9,
    0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2,
]

# Test binary NASM source
TEST_ASM = """\
%include "chacha20.inc"

section .data
    test_key: db 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07
              db 0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
              db 0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17
              db 0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    test_nonce: db 0x00,0x00,0x00,0x09,0x00,0x00,0x00,0x4a
                db 0x00,0x00,0x00,0x00

section .bss
    output_state: resb 64

section .text
global _start
_start:
    lea rdi, [rel test_key]
    mov esi, 1
    lea rdx, [rel test_nonce]
    lea rcx, [rel output_state]
    call chacha20_block

    ; write(1, output_state, 64)
    mov eax, 1
    mov edi, 1
    lea rsi, [rel output_state]
    mov edx, 64
    syscall

    ; exit(0)
    mov eax, 60
    xor edi, edi
    syscall
"""


def win_to_wsl(path):
    """Convert a Windows path to a WSL /mnt/ path."""
    path = os.path.abspath(path).replace("\\", "/")
    # Match drive letter, e.g. C:/... -> /mnt/c/...
    m = re.match(r"^([A-Za-z]):/(.*)$", path)
    if m:
        return f"/mnt/{m.group(1).lower()}/{m.group(2)}"
    return path


def main():
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    build_dir = os.path.join(project_root, "build")
    shared_dir = os.path.join(project_root, "shared")
    os.makedirs(build_dir, exist_ok=True)

    asm_path = os.path.join(build_dir, "test_chacha20.asm")
    obj_path = os.path.join(build_dir, "test_chacha20.o")
    bin_path = os.path.join(build_dir, "test_chacha20")

    # Write test assembly source
    with open(asm_path, "w") as f:
        f.write(TEST_ASM)

    # Step 1: Assemble with NASM (runs on Windows natively)
    print("[*] Assembling test binary...")
    result = subprocess.run(
        ["nasm", "-f", "elf64", f"-I{shared_dir}\\", "-o", obj_path, asm_path],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"[!] NASM failed:\n{result.stderr}")
        return False

    # Step 2: Link with ld in WSL
    print("[*] Linking test binary...")
    obj_wsl = win_to_wsl(obj_path)
    bin_wsl = win_to_wsl(bin_path)

    # Set MSYS_NO_PATHCONV to prevent Git Bash from mangling paths
    env = os.environ.copy()
    env["MSYS_NO_PATHCONV"] = "1"

    result = subprocess.run(
        ["wsl", "ld", "-o", bin_wsl, obj_wsl],
        capture_output=True, text=True, env=env
    )
    if result.returncode != 0:
        print(f"[!] ld failed:\n{result.stderr}")
        return False

    # Step 3: Run test binary in WSL
    print("[*] Running test binary...")
    result = subprocess.run(
        ["wsl", bin_wsl],
        capture_output=True, env=env
    )
    if result.returncode != 0:
        print(f"[!] Test binary exited with code {result.returncode}")
        print(f"    stderr: {result.stderr}")
        return False

    # Step 4: Verify output
    output = result.stdout
    if len(output) != 64:
        print(f"[!] Expected 64 bytes of output, got {len(output)}")
        return False

    # Unpack as 16 LE uint32
    actual_state = list(struct.unpack("<16I", output))

    print("[*] Comparing against RFC 8439 Section 2.3.2 test vector...")
    passed = True
    for i in range(16):
        status = "OK" if actual_state[i] == EXPECTED_STATE[i] else "FAIL"
        if status == "FAIL":
            passed = False
        print(f"    word[{i:2d}]: expected 0x{EXPECTED_STATE[i]:08x}, got 0x{actual_state[i]:08x} [{status}]")

    if passed:
        print("[+] ChaCha20 block test PASSED")
    else:
        print("[-] ChaCha20 block test FAILED")

    return passed


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
