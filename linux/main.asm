; ncat - encrypted netcat (Linux x86-64)
; Stub for build system verification

section .text
global _start

_start:
    ; exit(0)
    mov eax, 60
    xor edi, edi
    syscall
