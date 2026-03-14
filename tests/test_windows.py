#!/usr/bin/env python3
"""Integration tests for Windows grotto.exe encrypted relay and shell execution.

Run ON a Windows machine with Python 3.8+ and the 'cryptography' package installed:
    pip install cryptography
    python tests/test_windows.py
"""

import os
import secrets
import socket
import struct
import subprocess
import sys
import time

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# Locate grotto.exe: check build/ directory relative to this script, then current dir
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_BUILD_DIR = os.path.join(_SCRIPT_DIR, "..", "build")
if os.path.isfile(os.path.join(_BUILD_DIR, "grotto.exe")):
    GROTTO_BIN = os.path.join(_BUILD_DIR, "grotto.exe")
elif os.path.isfile("grotto.exe"):
    GROTTO_BIN = os.path.abspath("grotto.exe")
else:
    GROTTO_BIN = os.path.join(_BUILD_DIR, "grotto.exe")  # fallback, let it fail later


def make_key():
    """Generate a random 32-byte symmetric key."""
    return secrets.token_bytes(32)


def key_to_hex(key):
    """Convert a 32-byte key to its hex string representation."""
    return key.hex()


def recv_exact(sock, n):
    """Receive exactly n bytes from socket."""
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection closed")
        data += chunk
    return data


def send_encrypted(sock, key, plaintext):
    """Encrypt plaintext and send in wire protocol format.

    Wire format: [4B LE length][12B nonce][ciphertext][16B tag]
    The 4-byte length covers nonce + ciphertext + tag.
    """
    nonce = secrets.token_bytes(12)
    aead = ChaCha20Poly1305(key)
    ct_and_tag = aead.encrypt(nonce, plaintext, None)
    payload = nonce + ct_and_tag
    header = struct.pack("<I", len(payload))
    sock.sendall(header + payload)


def recv_encrypted(sock, key):
    """Receive wire protocol message and decrypt.

    Reads 4-byte LE length header, then payload = nonce(12) + ciphertext + tag(16).
    Returns decrypted plaintext bytes.
    """
    header = recv_exact(sock, 4)
    payload_len = struct.unpack("<I", header)[0]
    payload = recv_exact(sock, payload_len)
    nonce = payload[:12]
    ct_and_tag = payload[12:]
    aead = ChaCha20Poly1305(key)
    return aead.decrypt(nonce, ct_and_tag, None)


# ---------------------------------------------------------------------------
# Test 1: Encrypted relay (no -e) — use -e with a command that echoes back
# ---------------------------------------------------------------------------
def test_encrypted_relay():
    """Start grotto.exe listener with -e cmd.exe /c 'findstr .*' (echo),
    connect via Python, exchange encrypted messages."""
    print("Test 1: Encrypted relay (echo via findstr)...", end=" ", flush=True)

    key = make_key()
    key_hex = key_to_hex(key)
    port = 15551

    # Use 'cmd.exe /c more' as a simple echo-back: it reads stdin and writes to stdout.
    # However, the most reliable Windows echo-back is 'findstr ".*"' which echoes every line.
    proc = subprocess.Popen(
        [GROTTO_BIN, "-l", "-p", str(port), "-k", key_hex,
         "-e", "cmd.exe /c findstr .*"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )

    try:
        time.sleep(2)  # wait for listener

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(("127.0.0.1", port))

        # Send encrypted message
        test_data = b"hello_relay_test\n"
        send_encrypted(sock, key, test_data)

        # Receive encrypted response
        response = recv_encrypted(sock, key)
        response_text = response.decode("utf-8", errors="replace").strip()
        assert "hello_relay_test" in response_text, (
            f"Expected 'hello_relay_test' in response, got {response_text!r}"
        )

        sock.close()
        print("PASS")
    except Exception as e:
        print(f"FAIL: {e}")
        raise
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


# ---------------------------------------------------------------------------
# Test 2: Shell execution via -e cmd.exe
# ---------------------------------------------------------------------------
def test_shell_execution():
    """Start grotto.exe with -e cmd.exe, send encrypted 'echo hello_test',
    verify the encrypted response contains expected output."""
    print("Test 2: Encrypted shell execution (-e cmd.exe)...", end=" ", flush=True)

    key = make_key()
    key_hex = key_to_hex(key)
    port = 15552

    proc = subprocess.Popen(
        [GROTTO_BIN, "-l", "-p", str(port), "-k", key_hex, "-e", "cmd.exe"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )

    try:
        time.sleep(2)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(("127.0.0.1", port))

        # cmd.exe may send a banner first — try to drain it
        time.sleep(1)

        # Send command
        send_encrypted(sock, key, b"echo hello_test\r\n")

        # Read responses until we find our marker (cmd.exe may send prompt + output)
        found = False
        for _ in range(5):
            try:
                response = recv_encrypted(sock, key)
                response_text = response.decode("utf-8", errors="replace")
                if "hello_test" in response_text:
                    found = True
                    break
            except socket.timeout:
                break

        assert found, "Expected 'hello_test' in shell output"

        # Clean exit
        send_encrypted(sock, key, b"exit\r\n")
        time.sleep(0.5)
        sock.close()
        print("PASS")
    except Exception as e:
        print(f"FAIL: {e}")
        raise
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


# ---------------------------------------------------------------------------
# Test 3: Connect mode — Python listens, grotto.exe connects
# ---------------------------------------------------------------------------
def test_connect_mode():
    """Python opens a listener, grotto.exe connects to it, verify encrypted
    bidirectional communication works."""
    print("Test 3: Connect mode (grotto connects to Python)...", end=" ", flush=True)

    key = make_key()
    key_hex = key_to_hex(key)
    port = 15553

    # Python listens
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", port))
    server.listen(1)
    server.settimeout(10)

    # Start grotto.exe in connect mode with -e to echo back
    proc = subprocess.Popen(
        [GROTTO_BIN, "127.0.0.1", str(port), "-k", key_hex,
         "-e", "cmd.exe /c findstr .*"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )

    try:
        # Accept grotto connection
        conn, addr = server.accept()
        conn.settimeout(10)

        # Send encrypted data to grotto
        test_data = b"connect_mode_test\n"
        send_encrypted(conn, key, test_data)

        # Receive echoed response
        response = recv_encrypted(conn, key)
        response_text = response.decode("utf-8", errors="replace").strip()
        assert "connect_mode_test" in response_text, (
            f"Expected 'connect_mode_test' in response, got {response_text!r}"
        )

        conn.close()
        print("PASS")
    except Exception as e:
        print(f"FAIL: {e}")
        raise
    finally:
        server.close()
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print(f"Using binary: {GROTTO_BIN}")
    if not os.path.isfile(GROTTO_BIN):
        print(f"ERROR: Binary not found at {GROTTO_BIN}")
        sys.exit(1)

    passed = 0
    failed = 0
    errors = []

    for test_fn in [test_encrypted_relay, test_shell_execution, test_connect_mode]:
        try:
            test_fn()
            passed += 1
        except Exception as e:
            failed += 1
            errors.append((test_fn.__name__, str(e)))

    print(f"\nResults: {passed} passed, {failed} failed")
    if errors:
        for name, err in errors:
            print(f"  FAILED: {name}: {err}")
        sys.exit(1)
    else:
        print("All Windows tests passed!")
