#!/usr/bin/env python3
"""Test Poly1305 MAC against RFC 8439 Section 2.5.2 test vector."""

import subprocess
import os
import sys
import re


# RFC 8439 Section 2.5.2 expected tag (16 bytes)
EXPECTED_TAG = bytes([
    0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
    0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9,
])

# Test binary NASM source
TEST_ASM = """\
%include "poly1305.inc"

section .data
    test_key: db 0x85,0xd6,0xbe,0x78,0x57,0x55,0x6d,0x33
              db 0x7f,0x44,0x52,0xfe,0x42,0xd5,0x06,0xa8
              db 0x01,0x03,0x80,0x8a,0xfb,0x0d,0xb2,0xfd
              db 0x4a,0xbf,0xf6,0xaf,0x41,0x49,0xf5,0x1b
    test_msg: db "Cryptographic Forum Research Group"
    test_msg_len equ $ - test_msg

section .bss
    output_tag: resb 16

section .text
global _start
_start:
    lea rdi, [rel test_key]
    lea rsi, [rel test_msg]
    mov edx, test_msg_len
    lea rcx, [rel output_tag]
    call poly1305_mac

    ; write(1, output_tag, 16)
    mov eax, 1
    mov edi, 1
    lea rsi, [rel output_tag]
    mov edx, 16
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

    asm_path = os.path.join(build_dir, "test_poly1305.asm")
    obj_path = os.path.join(build_dir, "test_poly1305.o")
    bin_path = os.path.join(build_dir, "test_poly1305")

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
    if len(output) != 16:
        print(f"[!] Expected 16 bytes of output, got {len(output)}")
        if len(output) > 0:
            print(f"    Got: {output.hex()}")
        return False

    print("[*] Comparing against RFC 8439 Section 2.5.2 test vector...")
    print(f"    Expected: {EXPECTED_TAG.hex()}")
    print(f"    Got:      {output.hex()}")

    if output == EXPECTED_TAG:
        print("[+] Poly1305 MAC test PASSED")
        return True
    else:
        print("[-] Poly1305 MAC test FAILED")
        # Show byte-by-byte comparison
        for i in range(16):
            expected_byte = EXPECTED_TAG[i]
            actual_byte = output[i]
            status = "OK" if expected_byte == actual_byte else "FAIL"
            print(f"    byte[{i:2d}]: expected 0x{expected_byte:02x}, got 0x{actual_byte:02x} [{status}]")
        return False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
