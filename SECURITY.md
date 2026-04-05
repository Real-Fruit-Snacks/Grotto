# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest  | Yes       |

## Reporting a Vulnerability

**Do not open public GitHub issues for security vulnerabilities.**

### Preferred Method

Report vulnerabilities through [GitHub Security Advisories](https://github.com/Real-Fruit-Snacks/Grotto/security/advisories/new).

### Alternative

Contact the maintainers directly through GitHub with a detailed description of the vulnerability.

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 7 days
- **Resolution target**: Within 90 days

### Responsible Disclosure

We follow a 90-day responsible disclosure timeline. We ask that you:

1. Report the vulnerability privately
2. Allow reasonable time for a fix before public disclosure
3. Do not exploit the vulnerability beyond what is necessary to demonstrate it

### Scope

Security issues in the following areas are in scope:

- Cryptographic implementation (ChaCha20, Poly1305, AEAD)
- Wire protocol vulnerabilities
- Key handling and memory safety
- Buffer overflows or memory corruption
- Authentication bypass

### Out of Scope

- Social engineering
- Denial of service (unless caused by a specific code flaw)
- Issues in third-party dependencies (we have none)

## Authorization Notice

This tool is designed for authorized security testing only. Unauthorized use against systems you do not own or have explicit permission to test is illegal and unethical.
