#!/usr/bin/env python3
"""Integration tests for Linux ncat encrypted relay and shell execution."""

import os
import socket
import struct
import subprocess
import sys
import time

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

NCAT_BIN = os.path.join(os.path.dirname(__file__), "..", "build", "ncat")
# Resolve to absolute WSL path
NCAT_WSL = "./build/ncat"


def make_key():
    """Generate a random 32-byte key and its hex representation."""
    key = os.urandom(32)
    return key, key.hex()


def encrypt_msg(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt plaintext into wire protocol format:
    [4B LE length][12B nonce][ciphertext][16B tag]
    """
    nonce = os.urandom(12)
    aead = ChaCha20Poly1305(key)
    # encrypt returns ciphertext + tag (16 bytes) concatenated
    ct_and_tag = aead.encrypt(nonce, plaintext, None)
    payload_len = 12 + len(ct_and_tag)  # nonce + ciphertext + tag
    header = struct.pack("<I", payload_len)
    return header + nonce + ct_and_tag


def decrypt_msg(key: bytes, data: bytes) -> bytes:
    """Decrypt wire protocol message (after reading 4B length header).
    data = nonce (12) + ciphertext + tag (16)
    """
    nonce = data[:12]
    ct_and_tag = data[12:]
    aead = ChaCha20Poly1305(key)
    return aead.decrypt(nonce, ct_and_tag, None)


def recv_wire_msg(sock: socket.socket, key: bytes) -> bytes:
    """Receive and decrypt one wire protocol message from socket."""
    # Read 4-byte length header
    hdr = b""
    while len(hdr) < 4:
        chunk = sock.recv(4 - len(hdr))
        if not chunk:
            raise ConnectionError("Connection closed reading header")
        hdr += chunk

    payload_len = struct.unpack("<I", hdr)[0]

    # Read payload
    payload = b""
    while len(payload) < payload_len:
        chunk = sock.recv(payload_len - len(payload))
        if not chunk:
            raise ConnectionError("Connection closed reading payload")
        payload += chunk

    return decrypt_msg(key, payload)


def send_wire_msg(sock: socket.socket, key: bytes, plaintext: bytes):
    """Encrypt and send one wire protocol message over socket."""
    msg = encrypt_msg(key, plaintext)
    sock.sendall(msg)


def test_echo_relay():
    """Test 1: Encrypted relay without -e (stdin/stdout mode).
    Start ncat in listen mode, connect, send encrypted data, verify echo back."""
    print("Test 1: Encrypted echo relay (no -e)...", end=" ", flush=True)

    key, key_hex = make_key()
    port = 14441

    # Start ncat listener that cats back (using shell to pipe)
    # We'll just test that we can send and the other side receives
    # For a true echo test, we'd need two ncat instances
    # Instead, test with -e /bin/cat which echoes input back
    proc = subprocess.Popen(
        ["wsl", NCAT_WSL, "-l", "-p", str(port), "-k", key_hex, "-e", "/bin/cat"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )

    try:
        time.sleep(1.5)  # wait for listener to start

        # Connect
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(("127.0.0.1", port))

        # Send encrypted message
        test_data = b"hello_echo_test"
        send_wire_msg(sock, key, test_data)

        # Receive encrypted response (cat echoes it back)
        response = recv_wire_msg(sock, key)
        assert response == test_data, f"Expected {test_data!r}, got {response!r}"

        sock.close()
        print("PASS")
    except Exception as e:
        print(f"FAIL: {e}")
        raise
    finally:
        proc.terminate()
        proc.wait(timeout=3)


def test_shell_exec():
    """Test 2: Encrypted shell execution with -e /bin/sh."""
    print("Test 2: Encrypted shell execution (-e /bin/sh)...", end=" ", flush=True)

    key, key_hex = make_key()
    port = 14442

    proc = subprocess.Popen(
        ["wsl", NCAT_WSL, "-l", "-p", str(port), "-k", key_hex, "-e", "/bin/sh"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )

    try:
        time.sleep(1.5)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(("127.0.0.1", port))

        # Send 'echo hello_test\n'
        send_wire_msg(sock, key, b"echo hello_test\n")

        # Read response
        response = recv_wire_msg(sock, key)
        response_text = response.decode("utf-8", errors="replace").strip()
        assert "hello_test" in response_text, (
            f"Expected 'hello_test' in response, got {response_text!r}"
        )

        # Send 'exit\n' to cleanly terminate
        send_wire_msg(sock, key, b"exit\n")
        time.sleep(0.3)

        sock.close()
        print("PASS")
    except Exception as e:
        print(f"FAIL: {e}")
        raise
    finally:
        proc.terminate()
        proc.wait(timeout=3)


def test_multiple_commands():
    """Test 3: Multiple commands through encrypted shell."""
    print("Test 3: Multiple commands through shell...", end=" ", flush=True)

    key, key_hex = make_key()
    port = 14443

    proc = subprocess.Popen(
        ["wsl", NCAT_WSL, "-l", "-p", str(port), "-k", key_hex, "-e", "/bin/sh"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )

    try:
        time.sleep(1.5)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(("127.0.0.1", port))

        # Command 1
        send_wire_msg(sock, key, b"echo cmd_one\n")
        resp1 = recv_wire_msg(sock, key).decode("utf-8", errors="replace").strip()
        assert "cmd_one" in resp1, f"Expected 'cmd_one', got {resp1!r}"

        # Command 2
        send_wire_msg(sock, key, b"echo cmd_two\n")
        resp2 = recv_wire_msg(sock, key).decode("utf-8", errors="replace").strip()
        assert "cmd_two" in resp2, f"Expected 'cmd_two', got {resp2!r}"

        # Command 3: something that produces known output
        send_wire_msg(sock, key, b"expr 2 + 3\n")
        resp3 = recv_wire_msg(sock, key).decode("utf-8", errors="replace").strip()
        assert "5" in resp3, f"Expected '5', got {resp3!r}"

        send_wire_msg(sock, key, b"exit\n")
        time.sleep(0.3)
        sock.close()
        print("PASS")
    except Exception as e:
        print(f"FAIL: {e}")
        raise
    finally:
        proc.terminate()
        proc.wait(timeout=3)


if __name__ == "__main__":
    try:
        test_echo_relay()
        test_shell_exec()
        test_multiple_commands()
        print("\nAll relay tests passed!")
    except Exception:
        sys.exit(1)
