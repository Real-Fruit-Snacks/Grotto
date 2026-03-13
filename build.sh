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
