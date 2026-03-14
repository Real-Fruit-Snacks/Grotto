#!/usr/bin/env python3
"""Inspect PE section characteristics."""
import struct
import sys

with open(r"build\grotto.exe", "rb") as f:
    data = f.read()

# DOS header: e_lfanew at offset 0x3C
e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
print(f"PE header at offset: 0x{e_lfanew:X}")

# PE signature + COFF header
sig = data[e_lfanew:e_lfanew+4]
print(f"Signature: {sig}")

# COFF header at e_lfanew + 4
num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
opt_header_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
print(f"Number of sections: {num_sections}")
print(f"Optional header size: 0x{opt_header_size:X}")

# Entry point RVA in optional header
entry_rva = struct.unpack_from("<I", data, e_lfanew + 40)[0]
image_base = struct.unpack_from("<Q", data, e_lfanew + 48)[0]
print(f"Entry point RVA: 0x{entry_rva:X}")
print(f"Image base: 0x{image_base:X}")
print(f"Entry VA: 0x{image_base + entry_rva:X}")

# Section headers start at e_lfanew + 24 + opt_header_size
sec_offset = e_lfanew + 24 + opt_header_size
for i in range(num_sections):
    off = sec_offset + i * 40
    name = data[off:off+8].rstrip(b'\x00').decode()
    vsize = struct.unpack_from("<I", data, off+8)[0]
    vaddr = struct.unpack_from("<I", data, off+12)[0]
    rawsize = struct.unpack_from("<I", data, off+16)[0]
    rawoff = struct.unpack_from("<I", data, off+20)[0]
    chars = struct.unpack_from("<I", data, off+36)[0]

    flags = []
    if chars & 0x00000020: flags.append("CODE")
    if chars & 0x00000040: flags.append("INIT_DATA")
    if chars & 0x00000080: flags.append("UNINIT_DATA")
    if chars & 0x20000000: flags.append("EXEC")
    if chars & 0x40000000: flags.append("READ")
    if chars & 0x80000000: flags.append("WRITE")

    print(f"\n  [{i}] {name:8s} VA=0x{vaddr:08X} VSize=0x{vsize:X} "
          f"Raw=0x{rawoff:X}+0x{rawsize:X} Chars=0x{chars:08X} [{', '.join(flags)}]")
