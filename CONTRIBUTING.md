# Contributing to Grotto

Thank you for your interest in contributing to Grotto. This document provides guidelines for contributing to the project.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/Grotto.git`
3. Create a feature branch: `git checkout -b feature/your-feature`
4. Make your changes
5. Push to your fork: `git push origin feature/your-feature`
6. Open a Pull Request

## Development Setup

### Prerequisites

| Tool | Purpose |
|------|---------|
| NASM | Assembler (latest version) |
| MinGW-w64 | Windows linker (`x86_64-w64-mingw32-ld`) |
| GNU ld | Linux linker (via WSL or native Linux) |
| Python 3 | Build scripts and baked build generation |

### Building

```bash
# Build both targets
./build.sh

# Build individually
make linux
make windows

# Clean build artifacts
make clean
```

## Code Style

### Assembly Conventions

- Use lowercase for instructions and registers
- Use SCREAMING_CASE for constants and macros
- Use snake_case for labels and function names
- Comment non-obvious logic, especially crypto operations
- Keep line length under 120 characters where practical

### File Organization

- Platform-specific code goes in `linux/` or `windows/`
- Shared code (crypto) goes in `shared/` as `.inc` files
- Each file should have a clear single responsibility

## Pull Request Guidelines

### Before Submitting

- [ ] Code assembles without errors on both targets
- [ ] Both Linux and Windows binaries build successfully
- [ ] Test basic connectivity (listen + connect)
- [ ] Test encrypted shell relay (`-e` flag)
- [ ] Test baked builds if applicable
- [ ] No regressions in existing functionality

### PR Format

- Use a clear, descriptive title
- Reference any related issues
- Describe what changed and why
- Include testing steps

### Commit Messages

Use conventional commit format:

```
type: short description

Longer description if needed.
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `build`, `chore`

## What We Accept

- Bug fixes
- Performance improvements
- New platform support
- Crypto implementation improvements
- Documentation improvements
- Build system improvements

## What We Do Not Accept

- Dependencies on external libraries (the project must remain zero-dependency)
- High-level language wrappers
- Features that compromise the minimal binary size philosophy
- Code that only works on one platform without justification

## Security Vulnerabilities

**Do not open public issues for security vulnerabilities.** See [SECURITY.md](SECURITY.md) for responsible disclosure procedures.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
