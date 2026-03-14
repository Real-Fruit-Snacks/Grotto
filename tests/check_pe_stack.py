#!/usr/bin/env python3
import struct
with open(r"build\grotto.exe", "rb") as f:
    data = f.read()
e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
opt = e_lfanew + 24  # optional header starts after PE sig (4) + COFF header (20)
magic = struct.unpack_from("<H", data, opt)[0]
print(f"Optional header magic: 0x{magic:X} ({'PE32+' if magic == 0x20B else 'PE32' if magic == 0x10B else '?'})")

# PE32+ offsets (from optional header start)
stack_reserve = struct.unpack_from("<Q", data, opt + 72)[0]
stack_commit = struct.unpack_from("<Q", data, opt + 80)[0]
heap_reserve = struct.unpack_from("<Q", data, opt + 88)[0]
heap_commit = struct.unpack_from("<Q", data, opt + 96)[0]
print(f"Stack Reserve: {stack_reserve} (0x{stack_reserve:X}) = {stack_reserve//1024}KB")
print(f"Stack Commit:  {stack_commit} (0x{stack_commit:X}) = {stack_commit//1024}KB")
print(f"Heap Reserve:  {heap_reserve} (0x{heap_reserve:X})")
print(f"Heap Commit:   {heap_commit} (0x{heap_commit:X})")
print(f"\nThread buffer alloc: 131144 bytes ({131144//1024}KB)")
print(f"Stack reserve enough: {stack_reserve >= 131144 + 65536}")
