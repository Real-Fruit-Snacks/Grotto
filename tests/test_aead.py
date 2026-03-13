#!/usr/bin/env python3
"""Test ChaCha20-Poly1305 AEAD against Python cryptography library cross-validation."""

import subprocess
import struct
import os
import sys
import re

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


# RFC 8439 Section 2.8.2 test vector key and nonce
TEST_KEY = bytes([
    0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a,
    0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
    0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09,
    0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0,
])

TEST_NONCE = bytes([
    0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07, 0x08,
])

TEST_PLAINTEXT = (
    b"Ladies and Gentlemen of the class of '99: "
    b"If I could offer you only one tip for the future, sunscreen would be it."
)


def format_db_bytes(data, label):
    """Format bytes as NASM db lines."""
    lines = []
    for i in range(0, len(data), 8):
        chunk = data[i:i+8]
        hex_bytes = ",".join(f"0x{b:02x}" for b in chunk)
        prefix = f"    {label}: " if i == 0 else "              "
        lines.append(f"{prefix}db {hex_bytes}")
    return "\n".join(lines)


# Test A: Assembly encrypts, Python decrypts and verifies plaintext matches
TEST_ENCRYPT_ASM = """\
%include "aead.inc"

section .data
{key_data}
{nonce_data}
    test_plaintext: db {plaintext_bytes}
    test_pt_len equ $ - test_plaintext

section .bss
    output: resb test_pt_len + 16

section .text
global _start
_start:
    lea rdi, [rel test_key]
    lea rsi, [rel test_nonce]
    lea rdx, [rel test_plaintext]
    mov ecx, test_pt_len
    lea r8, [rel output]
    call aead_encrypt
    ; rax = output length

    ; write output to stdout
    mov edx, eax
    mov eax, 1
    mov edi, 1
    lea rsi, [rel output]
    syscall

    mov eax, 60
    xor edi, edi
    syscall
""".format(
    key_data=format_db_bytes(TEST_KEY, "test_key"),
    nonce_data=format_db_bytes(TEST_NONCE, "test_nonce"),
    plaintext_bytes=",".join(f"0x{b:02x}" for b in TEST_PLAINTEXT),
)


def make_decrypt_asm(ciphertext_with_tag):
    """Generate NASM source for decryption test binary."""
    ct = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]
    ct_len = len(ct)

    ct_bytes = ",".join(f"0x{b:02x}" for b in ct)
    tag_bytes = ",".join(f"0x{b:02x}" for b in tag)

    return """\
%include "aead.inc"

section .data
{key_data}
{nonce_data}
    test_ciphertext: db {ct_bytes}
    test_ct_len equ $ - test_ciphertext
    test_tag: db {tag_bytes}

section .bss
    output: resb test_ct_len

section .text
global _start
_start:
    lea rdi, [rel test_key]
    lea rsi, [rel test_nonce]
    lea rdx, [rel test_ciphertext]
    mov ecx, test_ct_len
    lea r8, [rel test_tag]
    lea r9, [rel output]
    call aead_decrypt

    ; Check for failure
    cmp rax, -1
    je .fail

    ; write plaintext to stdout
    mov edx, eax
    mov eax, 1
    mov edi, 1
    lea rsi, [rel output]
    syscall

    mov eax, 60
    xor edi, edi
    syscall

.fail:
    mov eax, 60
    mov edi, 1
    syscall
""".format(
        key_data=format_db_bytes(TEST_KEY, "test_key"),
        nonce_data=format_db_bytes(TEST_NONCE, "test_nonce"),
        ct_bytes=ct_bytes,
        tag_bytes=tag_bytes,
    )


def win_to_wsl(path):
    """Convert a Windows path to a WSL /mnt/ path."""
    path = os.path.abspath(path).replace("\\", "/")
    m = re.match(r"^([A-Za-z]):/(.*)$", path)
    if m:
        return f"/mnt/{m.group(1).lower()}/{m.group(2)}"
    return path


def build_and_run(asm_source, name, project_root):
    """Assemble, link, and run a test binary. Returns (success, stdout_bytes)."""
    build_dir = os.path.join(project_root, "build")
    shared_dir = os.path.join(project_root, "shared")
    os.makedirs(build_dir, exist_ok=True)

    asm_path = os.path.join(build_dir, f"{name}.asm")
    obj_path = os.path.join(build_dir, f"{name}.o")
    bin_path = os.path.join(build_dir, name)

    with open(asm_path, "w") as f:
        f.write(asm_source)

    # Assemble
    print(f"[*] Assembling {name}...")
    result = subprocess.run(
        ["nasm", "-f", "elf64", f"-I{shared_dir}\\", "-o", obj_path, asm_path],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"[!] NASM failed:\n{result.stderr}")
        return False, b""

    # Link
    print(f"[*] Linking {name}...")
    env = os.environ.copy()
    env["MSYS_NO_PATHCONV"] = "1"

    result = subprocess.run(
        ["wsl", "ld", "-o", win_to_wsl(bin_path), win_to_wsl(obj_path)],
        capture_output=True, text=True, env=env
    )
    if result.returncode != 0:
        print(f"[!] ld failed:\n{result.stderr}")
        return False, b""

    # Run
    print(f"[*] Running {name}...")
    result = subprocess.run(
        ["wsl", win_to_wsl(bin_path)],
        capture_output=True, env=env
    )
    if result.returncode != 0:
        print(f"[!] {name} exited with code {result.returncode}")
        if result.stderr:
            print(f"    stderr: {result.stderr}")
        return False, b""

    return True, result.stdout


def test_encrypt(project_root):
    """Test A: Assembly encrypts, Python decrypts and verifies."""
    print("=" * 60)
    print("Test A: Assembly encrypt -> Python decrypt cross-validation")
    print("=" * 60)

    ok, output = build_and_run(TEST_ENCRYPT_ASM, "test_aead_encrypt", project_root)
    if not ok:
        return False

    expected_len = len(TEST_PLAINTEXT) + 16
    if len(output) != expected_len:
        print(f"[!] Expected {expected_len} bytes of output, got {len(output)}")
        if output:
            print(f"    Got (hex): {output.hex()}")
        return False

    ct_with_tag = output
    print(f"    Ciphertext+tag ({len(ct_with_tag)} bytes): {ct_with_tag.hex()}")

    # Decrypt with Python cryptography library (empty AAD)
    aead = ChaCha20Poly1305(TEST_KEY)
    try:
        decrypted = aead.decrypt(TEST_NONCE, bytes(ct_with_tag), None)
    except Exception as e:
        print(f"[!] Python decryption failed: {e}")
        print("    This means the assembly AEAD output is invalid.")
        return False

    if decrypted == TEST_PLAINTEXT:
        print(f"[+] Test A PASSED: Python successfully decrypted assembly output")
        print(f"    Plaintext: {decrypted.decode('ascii', errors='replace')}")
        return True
    else:
        print(f"[-] Test A FAILED: Decrypted plaintext does not match")
        print(f"    Expected: {TEST_PLAINTEXT}")
        print(f"    Got:      {decrypted}")
        return False


def test_decrypt(project_root):
    """Test B: Python encrypts, assembly decrypts and verifies."""
    print()
    print("=" * 60)
    print("Test B: Python encrypt -> Assembly decrypt cross-validation")
    print("=" * 60)

    # Encrypt with Python (empty AAD)
    aead = ChaCha20Poly1305(TEST_KEY)
    ct_with_tag = aead.encrypt(TEST_NONCE, TEST_PLAINTEXT, None)
    print(f"    Python ciphertext+tag ({len(ct_with_tag)} bytes): {ct_with_tag.hex()}")

    # Build assembly decryptor with this ciphertext+tag
    decrypt_asm = make_decrypt_asm(ct_with_tag)
    ok, output = build_and_run(decrypt_asm, "test_aead_decrypt", project_root)
    if not ok:
        return False

    if len(output) != len(TEST_PLAINTEXT):
        print(f"[!] Expected {len(TEST_PLAINTEXT)} bytes of plaintext, got {len(output)}")
        if output:
            print(f"    Got (hex): {output.hex()}")
        return False

    if output == TEST_PLAINTEXT:
        print(f"[+] Test B PASSED: Assembly successfully decrypted Python output")
        print(f"    Plaintext: {output.decode('ascii', errors='replace')}")
        return True
    else:
        print(f"[-] Test B FAILED: Decrypted plaintext does not match")
        print(f"    Expected: {TEST_PLAINTEXT}")
        print(f"    Got:      {output}")
        return False


def main():
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    result_a = test_encrypt(project_root)
    result_b = test_decrypt(project_root)

    print()
    print("=" * 60)
    if result_a and result_b:
        print("[+] All AEAD tests PASSED")
    else:
        print("[-] Some AEAD tests FAILED")
        if not result_a:
            print("    - Test A (encrypt) FAILED")
        if not result_b:
            print("    - Test B (decrypt) FAILED")
    print("=" * 60)

    return result_a and result_b


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
