; ncat - encrypted netcat (Linux x86-64)
; CLI argument parsing entry point

default rel
bits 64

section .text
global _start

; ============================================================================
; strlen - get length of null-terminated string
; Input:  rdi = pointer to string
; Output: rax = length
; ============================================================================
strlen:
    xor eax, eax
.loop:
    cmp byte [rdi + rax], 0
    je .done
    inc rax
    jmp .loop
.done:
    ret

; ============================================================================
; print_stderr - write null-terminated string to stderr (fd 2)
; Input: rdi = pointer to null-terminated string
; Clobbers: rax, rdi, rsi, rdx
; ============================================================================
print_stderr:
    push rdi
    call strlen
    mov rdx, rax            ; length
    pop rsi                 ; buffer
    mov eax, 1              ; sys_write
    mov edi, 2              ; stderr
    syscall
    ret

; ============================================================================
; parse_ipv4 - convert "A.B.C.D" string to 32-bit network-order dword
; Input:  rdi = pointer to dotted-decimal string
; Output: eax = IPv4 address in network byte order
; ============================================================================
parse_ipv4:
    xor eax, eax           ; accumulated result (4 bytes)
    xor ecx, ecx           ; current octet value
    xor edx, edx           ; octet index (0-3)

.loop:
    movzx r8d, byte [rdi]
    test r8b, r8b
    jz .store_last

    cmp r8b, '.'
    je .store_octet

    ; accumulate digit: octet = octet * 10 + (char - '0')
    imul ecx, ecx, 10
    sub r8d, '0'
    add ecx, r8d
    inc rdi
    jmp .loop

.store_octet:
    ; store octet at correct position (network byte order = memory order)
    mov byte [rsp - 8 + rdx], cl
    xor ecx, ecx
    inc edx
    inc rdi
    jmp .loop

.store_last:
    mov byte [rsp - 8 + rdx], cl
    mov eax, [rsp - 8]
    ret

; ============================================================================
; parse_port - convert decimal string to 16-bit network byte order
; Input:  rdi = pointer to decimal string
; Output: ax = port in network byte order
; ============================================================================
parse_port:
    xor eax, eax           ; accumulated value

.loop:
    movzx ecx, byte [rdi]
    test cl, cl
    jz .done
    imul eax, eax, 10
    sub ecx, '0'
    add eax, ecx
    inc rdi
    jmp .loop

.done:
    ; swap bytes for network byte order
    xchg al, ah
    ret

; ============================================================================
; parse_hex - convert 64-char hex string to 32 bytes
; Input:  rdi = pointer to hex string
;         rsi = pointer to output buffer (32 bytes)
; ============================================================================
parse_hex:
    mov ecx, 32            ; 32 bytes to produce

.loop:
    ; high nibble
    movzx eax, byte [rdi]
    call .hex_digit
    shl al, 4
    mov dl, al

    ; low nibble
    movzx eax, byte [rdi + 1]
    call .hex_digit
    or dl, al

    mov [rsi], dl
    add rdi, 2
    inc rsi
    dec ecx
    jnz .loop
    ret

.hex_digit:
    ; convert single hex char in al to value 0-15
    cmp al, '9'
    jbe .is_digit
    cmp al, 'F'
    jbe .is_upper
    ; 'a'-'f'
    sub al, 'a' - 10
    ret
.is_upper:
    sub al, 'A' - 10
    ret
.is_digit:
    sub al, '0'
    ret

; ============================================================================
; cleanup_and_exit - zero key, kill child, exit(0)
; ============================================================================
cleanup_and_exit:
    ; Zero the key in memory
    lea rdi, [rel g_key]
    xor eax, eax
    mov ecx, 32
    rep stosb
    ; Kill child process if spawned
    mov rdi, [rel g_child_pid]
    test rdi, rdi
    jz .no_child
    mov eax, 62             ; sys_kill
    mov esi, 9              ; SIGKILL
    syscall
    mov eax, 61             ; sys_wait4
    mov rdi, [rel g_child_pid]
    xor esi, esi
    xor edx, edx
    xor r10, r10
    syscall
.no_child:
    mov eax, 60             ; sys_exit
    xor edi, edi
    syscall

%include "aead.inc"    ; shared crypto (includes chacha20.inc and poly1305.inc)
%include "net.asm"     ; networking
%include "crypto.asm"  ; nonce generation, wire protocol wrappers
%include "io.asm"      ; relay loop
%include "shell.asm"   ; shell execution

; ============================================================================
; _start - entry point, parse CLI arguments
; ============================================================================
_start:
    ; ELF entry: [rsp] = argc, [rsp+8] = argv[0], [rsp+16] = argv[1], ...
    mov r12, [rsp]          ; r12 = argc
    lea r13, [rsp + 8]      ; r13 = &argv[0]

    ; Initialize tracking flags
    xor eax, eax
    mov [rel g_has_listen], al
    mov [rel g_has_connect], al
    mov [rel g_has_port], al
    mov [rel g_has_key], al
    mov byte [rel g_mode], 0xFF  ; 0xFF = not set
    mov qword [rel g_exec], 0
    mov qword [rel g_child_pid], 0

    ; Walk argv[1] .. argv[argc-1]
    mov r14, 1              ; i = 1 (skip argv[0])

.arg_loop:
    cmp r14, r12
    jge .done_parsing

    mov rsi, [r13 + r14 * 8]  ; rsi = argv[i]

    ; Check first char is '-'
    cmp byte [rsi], '-'
    jne .next_arg

    ; Check second char
    movzx eax, byte [rsi + 1]

    cmp al, 'l'
    je .flag_listen

    cmp al, 'c'
    je .flag_connect

    cmp al, 'p'
    je .flag_port

    cmp al, 'k'
    je .flag_key

    cmp al, 'e'
    je .flag_exec

    jmp .next_arg

.flag_listen:
    mov byte [rel g_has_listen], 1
    mov byte [rel g_mode], 1
    inc r14
    jmp .arg_loop

.flag_connect:
    mov byte [rel g_has_connect], 1
    mov byte [rel g_mode], 0
    ; consume next arg as host
    inc r14
    cmp r14, r12
    jge .done_parsing       ; no more args
    mov rdi, [r13 + r14 * 8]
    call parse_ipv4
    mov [rel g_host], eax
    inc r14
    jmp .arg_loop

.flag_port:
    mov byte [rel g_has_port], 1
    ; consume next arg as port
    inc r14
    cmp r14, r12
    jge .done_parsing
    mov rdi, [r13 + r14 * 8]
    call parse_port
    mov [rel g_port], ax
    inc r14
    jmp .arg_loop

.flag_key:
    mov byte [rel g_has_key], 1
    ; consume next arg as hex key
    inc r14
    cmp r14, r12
    jge .done_parsing
    mov rdi, [r13 + r14 * 8]
    lea rsi, [rel g_key]
    call parse_hex
    inc r14
    jmp .arg_loop

.flag_exec:
    ; consume next arg as exec command
    inc r14
    cmp r14, r12
    jge .done_parsing
    mov rax, [r13 + r14 * 8]
    mov [rel g_exec], rax
    inc r14
    jmp .arg_loop

.next_arg:
    inc r14
    jmp .arg_loop

.done_parsing:
    ; --- Validation ---

    ; Check for conflict: both -l and -c
    mov al, [rel g_has_listen]
    test al, al
    jz .no_conflict
    mov al, [rel g_has_connect]
    test al, al
    jz .no_conflict
    ; Both set - error
    lea rdi, [rel err_conflict]
    call print_stderr
    jmp .exit_error

.no_conflict:
    ; Check mode was set (either -l or -c given)
    cmp byte [rel g_mode], 0xFF
    jne .mode_ok
    lea rdi, [rel err_nomode]
    call print_stderr
    lea rdi, [rel usage_msg]
    call print_stderr
    jmp .exit_error

.mode_ok:
    ; Check -p was given
    cmp byte [rel g_has_port], 0
    jne .port_ok
    lea rdi, [rel err_port]
    call print_stderr
    jmp .exit_error

.port_ok:
    ; Check -k was given
    cmp byte [rel g_has_key], 0
    jne .parsed_ok
    lea rdi, [rel err_key]
    call print_stderr
    jmp .exit_error

.parsed_ok:
    ; Networking
    cmp byte [rel g_mode], 1
    je .listen_mode

.connect_mode:
    mov edi, [rel g_host]
    mov si, [rel g_port]
    call net_connect
    test rax, rax
    js .exit_error
    mov [rel g_sockfd], rax
    jmp .connected

.listen_mode:
    movzx edi, word [rel g_port]
    call net_listen
    test rax, rax
    js .exit_error
    mov [rel g_sockfd], rax

.connected:
    ; Check if -e flag was given
    cmp qword [rel g_exec], 0
    jne .spawn_shell

    ; No -e: relay between socket and stdin/stdout
    mov edi, [rel g_sockfd]
    mov esi, 0              ; local_read_fd = stdin
    mov edx, 1              ; local_write_fd = stdout
    call relay_loop
    ; relay_loop never returns

.spawn_shell:
    mov rdi, [rel g_exec]
    call spawn_shell
    cmp eax, -1
    je .exit_error
    ; eax = read_fd (child stdout), edx = write_fd (child stdin)
    mov esi, eax            ; local_read_fd = child stdout pipe
    ; edx already = local_write_fd = child stdin pipe
    mov edi, [rel g_sockfd]
    call relay_loop
    ; relay_loop never returns

.exit_error:
    mov eax, 60
    mov edi, 1
    syscall

; ============================================================================
; Data sections
; ============================================================================
section .bss
    g_mode:          resb 1      ; 0=connect, 1=listen, 0xFF=not set
    g_has_listen:    resb 1      ; tracking flag
    g_has_connect:   resb 1      ; tracking flag
    g_has_port:      resb 1      ; tracking flag
    g_has_key:       resb 1      ; tracking flag
    g_host:          resd 1      ; IPv4 network order
    g_port:          resw 1      ; network byte order
    g_key:           resb 32     ; 256-bit PSK
    g_exec:          resq 1      ; pointer to -e command (0 if none)
    g_sockfd:        resq 1      ; connected socket fd
    g_child_pid:     resq 1      ; child PID from fork
    g_shell_write_fd: resd 1     ; write fd to child stdin pipe

section .rodata
    usage_msg:   db "Usage: ncat [-l] [-c <host>] -p <port> -k <hex-key> [-e <cmd>]", 10, 0
    err_port:    db "Error: -p <port> is required", 10, 0
    err_key:     db "Error: -k <64-char-hex-key> is required", 10, 0
    err_conflict: db "Error: -l and -c cannot both be set", 10, 0
    err_nomode:  db "Error: must specify -l (listen) or -c (connect)", 10, 0
