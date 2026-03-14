#!/usr/bin/env python3
"""Generate baked.inc with compile-time configuration for Grotto."""
import argparse
import sys

def main():
    p = argparse.ArgumentParser(description="Generate baked NASM config")
    p.add_argument('--mode', choices=['listen', 'connect'], required=True)
    p.add_argument('--host', help='Target IP (required for connect mode)')
    p.add_argument('--port', type=int, required=True)
    p.add_argument('--key', required=True, help='64-char hex key')
    p.add_argument('--exec', dest='exec_cmd', help='Command to execute (-e)')
    p.add_argument('-o', '--output', default='build/baked.inc')
    args = p.parse_args()

    if args.mode == 'connect' and not args.host:
        print("Error: --host required for connect mode", file=sys.stderr)
        sys.exit(1)

    if len(args.key) != 64:
        print("Error: key must be 64 hex characters", file=sys.stderr)
        sys.exit(1)

    try:
        key_bytes = bytes.fromhex(args.key)
    except ValueError:
        print("Error: key must be valid hex", file=sys.stderr)
        sys.exit(1)

    mode_val = 1 if args.mode == 'listen' else 0

    # IP as little-endian dword of network-order bytes
    if args.host:
        octets = [int(x) for x in args.host.split('.')]
        ip_dword = octets[0] | (octets[1] << 8) | (octets[2] << 16) | (octets[3] << 24)
    else:
        ip_dword = 0

    # Port in network byte order, stored as LE word
    port_net = ((args.port >> 8) & 0xFF) | ((args.port & 0xFF) << 8)

    with open(args.output, 'w') as f:
        f.write("; Auto-generated baked configuration\n\n")
        f.write(f"%define BAKED_MODE {mode_val}\n")
        f.write(f"%define BAKED_IP_DWORD 0x{ip_dword:08X}\n")
        f.write(f"%define BAKED_PORT_NET 0x{port_net:04X}\n")
        if args.exec_cmd:
            f.write("%define BAKED_HAS_EXEC\n")
        f.write("\n")

        f.write("section .rodata\n")
        f.write("baked_key_data:\n")
        for i in range(0, 32, 16):
            chunk = key_bytes[i:i+16]
            f.write("    db " + ', '.join(f'0x{b:02X}' for b in chunk) + "\n")
        f.write("\n")

        if args.exec_cmd:
            f.write("baked_exec_data:\n")
            f.write(f'    db "{args.exec_cmd}", 0\n\n')

        f.write("section .text\n")

    print(f"[*] Baked config: mode={'listen' if mode_val else 'connect'}"
          f" port={args.port} exec={args.exec_cmd or 'none'}")

if __name__ == '__main__':
    main()
