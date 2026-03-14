#!/usr/bin/env python3
"""Test grotto with large output commands on remote target."""
import paramiko
import time

TARGET = "192.168.123.147"
USER = "Eric.Wallows"
PASS = "EricLikesRunning800"
REMOTE_EXE = r"C:\Users\Eric.Wallows\Desktop\grotto.exe"
KEY = "41" * 32
PORT = 47780

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(TARGET, username=USER, password=PASS, timeout=10)
print("[+] Connected to target")

# Cleanup any old processes
ssh.exec_command('taskkill /IM grotto.exe /F 2>nul', timeout=5)
time.sleep(1)

def run_test(name, command, min_bytes=0, min_lines=0, timeout_sec=30):
    """Start listener+client, send command, collect output, verify size."""
    print(f"\n{'='*60}")
    print(f"[*] Test: {name}")
    print(f"[*] Command: {command}")
    print(f"{'='*60}")

    transport = ssh.get_transport()

    # Start listener
    chan_listen = transport.open_session()
    chan_listen.settimeout(5)
    chan_listen.exec_command(f'"{REMOTE_EXE}" -l -p {PORT} -k {KEY} -e cmd.exe')
    time.sleep(2)

    if chan_listen.exit_status_ready():
        ec = chan_listen.recv_exit_status()
        print(f"[FAIL] Listener exited early: 0x{ec & 0xFFFFFFFF:08X}")
        return False

    # Connect client
    chan_client = transport.open_session()
    chan_client.settimeout(timeout_sec)
    chan_client.exec_command(f'"{REMOTE_EXE}" -c 127.0.0.1 -p {PORT} -k {KEY}')
    time.sleep(2)

    if chan_client.exit_status_ready():
        ec = chan_client.recv_exit_status()
        print(f"[FAIL] Client exited early: 0x{ec & 0xFFFFFFFF:08X}")
        ssh.exec_command('taskkill /IM grotto.exe /F 2>nul', timeout=5)
        time.sleep(1)
        return False

    # Drain banner
    time.sleep(1)
    while chan_client.recv_ready():
        chan_client.recv(4096)

    # Send command
    chan_client.send(command.encode() + b"\r\n")

    # Collect output with timeout
    output = b""
    deadline = time.time() + timeout_sec
    idle_count = 0
    while time.time() < deadline:
        if chan_client.recv_ready():
            chunk = chan_client.recv(65536)
            if chunk:
                output += chunk
                idle_count = 0
                continue
        idle_count += 1
        if idle_count > 10 and len(output) > 0:
            # 10 consecutive idle checks with data already received = done
            break
        if chan_client.exit_status_ready():
            # Drain remaining
            while chan_client.recv_ready():
                output += chan_client.recv(65536)
            break
        time.sleep(0.5)

    total_bytes = len(output)
    text = output.decode(errors='replace')
    total_lines = text.count('\n')

    print(f"[*] Received: {total_bytes:,} bytes, {total_lines:,} lines")
    if total_bytes > 500:
        print(f"[*] First 200 chars: {text[:200]!r}")
        print(f"[*] Last 200 chars:  {text[-200:]!r}")
    else:
        print(f"[*] Output: {text!r}")

    # Cleanup
    try:
        chan_client.send(b"exit\r\n")
    except:
        pass
    ssh.exec_command('taskkill /IM grotto.exe /F 2>nul', timeout=5)
    time.sleep(1)

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


results = []

# Test 1: dir /s C:\Windows\System32 — massive directory listing (thousands of lines)
results.append(run_test(
    "Large dir listing",
    "dir /s C:\\Windows\\System32\\*.dll",
    min_lines=100,
    min_bytes=5000,
    timeout_sec=30
))

# Test 2: type a large file — systeminfo produces moderate output
results.append(run_test(
    "systeminfo (moderate output)",
    "systeminfo",
    min_lines=20,
    min_bytes=1000,
    timeout_sec=30
))

# Test 3: Generate large output with a loop — 1000 echo lines
results.append(run_test(
    "1000 echo lines",
    'for /L %i in (1,1,1000) do @echo Line %i: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    min_lines=500,
    min_bytes=30000,
    timeout_sec=45
))

# Test 4: ipconfig /all — moderate structured output
results.append(run_test(
    "ipconfig /all",
    "ipconfig /all",
    min_lines=10,
    min_bytes=500,
    timeout_sec=15
))

# Test 5: Large single-line output — 4000 chars on one line
results.append(run_test(
    "Long single line (4000 chars)",
    'cmd /c "set S=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnop& echo %S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%%S%"',
    min_bytes=100,
    timeout_sec=15
))

# Test 6: Rapid sequential commands
print(f"\n{'='*60}")
print("[*] Test: Rapid sequential commands (10 commands)")
print(f"{'='*60}")
transport = ssh.get_transport()
chan_listen = transport.open_session()
chan_listen.settimeout(5)
chan_listen.exec_command(f'"{REMOTE_EXE}" -l -p {PORT} -k {KEY} -e cmd.exe')
time.sleep(2)
chan_client = transport.open_session()
chan_client.settimeout(20)
chan_client.exec_command(f'"{REMOTE_EXE}" -c 127.0.0.1 -p {PORT} -k {KEY}')
time.sleep(2)
# Drain banner
while chan_client.recv_ready():
    chan_client.recv(4096)

rapid_pass = True
for i in range(10):
    marker = f"RAPID_{i}_{int(time.time())}"
    chan_client.send(f"echo {marker}\r\n".encode())
    time.sleep(1)
    out = b""
    while chan_client.recv_ready():
        out += chan_client.recv(4096)
    text = out.decode(errors='replace')
    if marker in text:
        print(f"  [{i+1}/10] PASS — got marker")
    else:
        print(f"  [{i+1}/10] FAIL — marker not found in: {text[:100]!r}")
        rapid_pass = False

try:
    chan_client.send(b"exit\r\n")
except:
    pass
ssh.exec_command('taskkill /IM grotto.exe /F 2>nul', timeout=5)
time.sleep(1)

if rapid_pass:
    print("[PASS] Rapid sequential commands")
else:
    print("[FAIL] Rapid sequential commands")
results.append(rapid_pass)

# Summary
ssh.close()
passed = sum(results)
total = len(results)
print(f"\n{'='*60}")
print(f"Results: {passed}/{total} passed")
if passed == total:
    print("All large output tests PASSED!")
else:
    print(f"{total - passed} test(s) FAILED")
print(f"{'='*60}")
