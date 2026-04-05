# Changelog

All notable changes to Grotto will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Initial public release
- ChaCha20-Poly1305 AEAD encryption (RFC 8439)
- Cross-platform support (Linux ELF + Windows PE)
- Bidirectional encrypted relay
- Interactive shell execution (`-e` flag)
- Baked builds with embedded configuration
- PEB walking with ror13 hash resolution (Windows)
- Raw syscalls with no libc dependency (Linux)
- 256-bit pre-shared key authentication
- Per-message random nonce generation
- Memory-safe key zeroing on exit
