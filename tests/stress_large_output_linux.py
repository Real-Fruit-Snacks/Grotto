#!/usr/bin/env python3
"""Test grotto Linux binary with large output commands locally via WSL."""
import subprocess
import socket
import struct
import os
import time
import secrets

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

KEY_BYTES = secrets.token_bytes(32)
KEY_HEX = KEY_BYTES.hex()
BASE_PORT = 48800
GROTTO = "./build/grotto"


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection closed")
        data += chunk
    return data


def send_encrypted(sock, plaintext):
    nonce = secrets.token_bytes(12)
    ct = ChaCha20Poly1305(KEY_BYTES).encrypt(nonce, plaintext, None)
    payload = nonce + ct
    sock.sendall(struct.pack("<I", len(payload)) + payload)


def recv_encrypted(sock):
    hdr = recv_exact(sock, 4)
    plen = struct.unpack("<I", hdr)[0]
    payload = recv_exact(sock, plen)
    return ChaCha20Poly1305(KEY_BYTES).decrypt(payload[:12], payload[12:], None)


def recv_all_encrypted(sock, timeout=10):
    """Receive all available encrypted messages until timeout."""
    output = b""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            msg = recv_encrypted(sock)
            output += msg
        except (socket.timeout, ConnectionError):
            if output:
                break
    return output


def run_test(name, command, port, min_bytes=0, min_lines=0, timeout_sec=15):
    print(f"\n{'='*60}")
    print(f"[*] Test: {name}")
    print(f"[*] Command: {command}")
    print(f"{'='*60}")

    # Start listener with -e /bin/sh
    proc = subprocess.Popen(
        ["wsl", GROTTO, "-l", "-p", str(port), "-k", KEY_HEX, "-e", "/bin/sh"],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
    )
    time.sleep(1.5)

    if proc.poll() is not None:
        print(f"[FAIL] Listener exited with code {proc.returncode}")
        return False

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect(("127.0.0.1", port))

        # Send the command
        send_encrypted(sock, (command + "\n").encode())

        # Collect output
        output = b""
        deadline = time.time() + timeout_sec
        idle = 0
        while time.time() < deadline:
            try:
                sock.settimeout(1)
                msg = recv_encrypted(sock)
                output += msg
                idle = 0
            except (socket.timeout, ConnectionError):
                idle += 1
                if idle > 3 and len(output) > 0:
                    break

        total_bytes = len(output)
        text = output.decode(errors='replace')
        total_lines = text.count('\n')

        print(f"[*] Received: {total_bytes:,} bytes, {total_lines:,} lines")
        if total_bytes > 500:
            print(f"[*] First 200 chars: {text[:200]!r}")
            print(f"[*] Last 200 chars:  {text[-200:]!r}")
        else:
            print(f"[*] Output: {text!r}")

        sock.close()

        passed = True
        if min_bytes and total_bytes < min_bytes:
            print(f"[FAIL] Expected >= {min_bytes:,} bytes, got {total_bytes:,}")
            passed = False
        if min_lines and total_lines < min_lines:
            print(f"[FAIL] Expected >= {min_lines:,} lines, got {total_lines:,}")
            passed = False
        if passed:
            print(f"[PASS] {name}")
        return passed

    except Exception as e:
        print(f"[FAIL] {e}")
        return False
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except:
            proc.kill()


results = []
port = BASE_PORT

# Test 1: Large directory listing
port += 1
results.append(run_test(
    "Large dir listing (find /usr)",
    "find /usr -name '*.so' 2>/dev/null",
    port, min_lines=50, min_bytes=2000, timeout_sec=20
))

# Test 2: /proc info
port += 1
results.append(run_test(
    "cat /proc/cpuinfo",
    "cat /proc/cpuinfo",
    port, min_lines=10, min_bytes=500, timeout_sec=10
))

# Test 3: 1000 echo lines
port += 1
results.append(run_test(
    "1000 echo lines",
    "for i in $(seq 1 1000); do echo \"Line $i: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"; done",
    port, min_lines=500, min_bytes=30000, timeout_sec=30
))

# Test 4: env dump
port += 1
results.append(run_test(
    "env dump",
    "env",
    port, min_lines=5, min_bytes=100, timeout_sec=10
))

# Test 5: Generate large single block with dd
port += 1
results.append(run_test(
    "dd 64KB of hex data",
    "cat /dev/urandom | head -c 4096 | od -A x -t x1z | head -256",
    port, min_lines=50, min_bytes=5000, timeout_sec=15
))

# Test 6: Rapid sequential commands
port += 1
print(f"\n{'='*60}")
print("[*] Test: Rapid sequential commands (10 commands)")
print(f"{'='*60}")

proc = subprocess.Popen(
    ["wsl", GROTTO, "-l", "-p", str(port), "-k", KEY_HEX, "-e", "/bin/sh"],
    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
)
time.sleep(1.5)

rapid_pass = True
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect(("127.0.0.1", port))

    for i in range(10):
        marker = f"RAPID_{i}_{secrets.token_hex(4)}"
        send_encrypted(sock, f"echo {marker}\n".encode())
        time.sleep(0.5)
        try:
            sock.settimeout(2)
            resp = recv_encrypted(sock)
            text = resp.decode(errors='replace')
            if marker in text:
                print(f"  [{i+1}/10] PASS - got marker")
            else:
                print(f"  [{i+1}/10] FAIL - marker not in: {text[:100]!r}")
                rapid_pass = False
        except (socket.timeout, ConnectionError):
            print(f"  [{i+1}/10] FAIL - no response")
            rapid_pass = False

    sock.close()
except Exception as e:
    print(f"[FAIL] {e}")
    rapid_pass = False
finally:
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except:
        proc.kill()

if rapid_pass:
    print("[PASS] Rapid sequential commands")
else:
    print("[FAIL] Rapid sequential commands")
results.append(rapid_pass)

# Summary
passed = sum(results)
total = len(results)
print(f"\n{'='*60}")
print(f"Results: {passed}/{total} passed")
if passed == total:
    print("All Linux large output tests PASSED!")
else:
    print(f"{total - passed} test(s) FAILED")
print(f"{'='*60}")
