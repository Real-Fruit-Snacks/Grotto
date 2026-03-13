; io.asm - Poll-based bidirectional encrypted relay loop
; Included into main.asm — shares its section .text

; Constants
%define POLLIN  0x0001
%define POLLERR 0x0008
%define POLLHUP 0x0010

; Stack layout offsets (from rsp):
;   [rsp+0]         - pollfd[0] (8 bytes): socket_fd
;   [rsp+8]         - pollfd[1] (8 bytes): local_read_fd
;   [rsp+16]        - length header buf (4 bytes, 8 aligned)
;   [rsp+24]        - recv buffer (65568 bytes = 65536 + 32)
;   [rsp+65592]     - send buffer (65568 bytes = 65536 + 32)
;   [rsp+131160]    - plaintext buffer (65536 bytes)
; Total: 196696 bytes

%define STK_POLLFDS      0
%define STK_POLLFD1      8
%define STK_LENHDR       16
%define STK_RECVBUF      24
%define STK_SENDBUF      65592
%define STK_PLAINBUF     131160
%define STK_TOTAL        196696

; ============================================================================
; relay_loop - Bidirectional encrypted relay using poll(2)
; Input:  edi = socket_fd, esi = local_read_fd, edx = local_write_fd
; Does not return — jumps to cleanup_and_exit when done
; ============================================================================
relay_loop:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15

    mov r12d, edi               ; socket_fd
    mov r13d, esi               ; local_read_fd
    mov r14d, edx               ; local_write_fd

    ; Allocate stack space
    sub rsp, STK_TOTAL

    ; Set up pollfd[0] = {socket_fd, POLLIN, 0}
    mov dword [rsp + STK_POLLFDS], r12d       ; fd
    mov word  [rsp + STK_POLLFDS + 4], POLLIN ; events
    mov word  [rsp + STK_POLLFDS + 6], 0      ; revents

    ; Set up pollfd[1] = {local_read_fd, POLLIN, 0}
    mov dword [rsp + STK_POLLFD1], r13d       ; fd
    mov word  [rsp + STK_POLLFD1 + 4], POLLIN ; events
    mov word  [rsp + STK_POLLFD1 + 6], 0      ; revents

.poll_loop:
    ; Reset revents
    mov word [rsp + STK_POLLFDS + 6], 0
    mov word [rsp + STK_POLLFD1 + 6], 0

    ; poll(pollfds, 2, -1)
    mov eax, 7                  ; sys_poll
    lea rdi, [rsp + STK_POLLFDS]
    mov esi, 2                  ; nfds
    mov edx, -1                 ; timeout = infinite
    syscall
    test eax, eax
    js .relay_exit              ; poll error

    ; --- Check socket for POLLERR|POLLHUP ---
    movzx eax, word [rsp + STK_POLLFDS + 6]
    test ax, POLLERR | POLLHUP
    jnz .relay_exit

    ; --- Check local_read for POLLERR|POLLHUP ---
    movzx eax, word [rsp + STK_POLLFD1 + 6]
    test ax, POLLERR | POLLHUP
    jnz .relay_exit

    ; --- Check socket for POLLIN (data from remote) ---
    movzx eax, word [rsp + STK_POLLFDS + 6]
    test ax, POLLIN
    jz .check_local

    ; Read 4-byte length header from socket
    mov edi, r12d
    lea rsi, [rsp + STK_LENHDR]
    mov edx, 4
    call recv_exact
    test rax, rax
    jnz .relay_exit             ; error or EOF

    ; Get payload length (LE 32-bit)
    mov ebp, [rsp + STK_LENHDR]

    ; Validate length: must be > 28 (12 nonce + 1 min ct + 16 tag - 1) and <= 65536
    cmp ebp, 29
    jb .relay_exit
    cmp ebp, 65536
    ja .relay_exit

    ; Read payload into recv buffer
    mov edi, r12d
    lea rsi, [rsp + STK_RECVBUF]
    mov edx, ebp
    call recv_exact
    test rax, rax
    jnz .relay_exit

    ; Decrypt: decrypt_message(recv_buf, payload_len, plaintext_buf)
    lea rdi, [rsp + STK_RECVBUF]
    mov esi, ebp
    lea rdx, [rsp + STK_PLAINBUF]
    call decrypt_message
    cmp rax, -1
    je .relay_exit              ; MAC failure

    ; Write plaintext to local_write_fd
    mov r15, rax                ; plaintext length
    mov eax, 1                  ; sys_write
    mov edi, r14d
    lea rsi, [rsp + STK_PLAINBUF]
    mov rdx, r15
    syscall
    test rax, rax
    js .relay_exit

.check_local:
    ; --- Check local_read for POLLIN (data from local) ---
    movzx eax, word [rsp + STK_POLLFD1 + 6]
    test ax, POLLIN
    jz .poll_loop

    ; Read from local_read_fd into plaintext buffer
    mov eax, 0                  ; sys_read
    mov edi, r13d
    lea rsi, [rsp + STK_PLAINBUF]
    mov edx, 65536
    syscall
    test rax, rax
    jz .relay_exit              ; EOF
    js .relay_exit              ; error

    mov r15, rax                ; bytes read

    ; Encrypt: encrypt_message(plaintext_buf, read_len, send_buf)
    lea rdi, [rsp + STK_PLAINBUF]
    mov esi, r15d
    lea rdx, [rsp + STK_SENDBUF]
    call encrypt_message
    cmp rax, -1
    je .relay_exit

    ; Send encrypted data over socket
    mov edi, r12d
    lea rsi, [rsp + STK_SENDBUF]
    mov rdx, rax                ; total wire length
    call send_all

    jmp .poll_loop

.relay_exit:
    add rsp, STK_TOTAL
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    jmp cleanup_and_exit
