#!/usr/bin/env python3
"""Verify ror13 hashes match expected API function names."""

def ror13_hash(name):
    h = 0
    for c in name:
        h = ((h >> 13) | (h << 19)) & 0xFFFFFFFF
        h = (h + ord(c)) & 0xFFFFFFFF
    return h

# kernel32.dll functions
kernel32 = {
    "CreateProcessA":       0x16b3fe72,
    "CreateThread":         0xca2bd06b,
    "WaitForSingleObject":  0xce05d9ad,
    "WaitForMultipleObjects": 0x23ead524,
    "CreatePipe":           0x170c8f80,
    "ReadFile":             0x10fa6516,
    "WriteFile":            0xe80a791f,
    "CloseHandle":          0x0ffd97fb,
    "ExitProcess":          0x73e2d87e,
    "GetCommandLineA":      0x36ef7370,
    "SetHandleInformation": 0x7f9e1144,
    "TerminateProcess":     0x78b5b983,
    "LoadLibraryA":         0xec0e4e8e,
    "GetProcAddress":       0x7c0dfcaa,
    "GetStdHandle":         0x7487d823,
}

# ws2_32.dll functions
ws2_32 = {
    "WSAStartup":   0x3bfcedcb,
    "socket":       0x492f0b6e,
    "bind":         0xc7701aa4,
    "listen":       0xe92eada4,
    "accept":       0x498649e5,
    "connect":      0x60aaf9ec,
    "send":         0xe97019a4,
    "recv":         0xe71819b6,
    "closesocket":  0x79c679e7,
}

# advapi32.dll
advapi32 = {
    "SystemFunction036": 0xa8a1833c,
}

all_ok = True
for dll_name, funcs in [("kernel32", kernel32), ("ws2_32", ws2_32), ("advapi32", advapi32)]:
    print(f"\n{dll_name}.dll:")
    for name, expected in funcs.items():
        computed = ror13_hash(name)
        match = "OK" if computed == expected else "MISMATCH"
        if computed != expected:
            all_ok = False
            print(f"  {name}: expected 0x{expected:08x}, got 0x{computed:08x} *** {match} ***")
        else:
            print(f"  {name}: 0x{computed:08x} {match}")

print(f"\n{'ALL HASHES CORRECT' if all_ok else 'HASH MISMATCHES FOUND!'}")
