; net.asm - Linux x86-64 socket functions (direct syscalls)
; Included into main.asm — shares its section .text

; ============================================================================
; net_listen - bind and accept one TCP connection
; Input:  di = port (network byte order, 16-bit)
; Output: rax = connected socket fd (negative on error)
; ============================================================================
net_listen:
    push rbx
    push r12
    movzx r12d, di              ; save port

    ; socket(AF_INET=2, SOCK_STREAM=1, 0)
    mov eax, 41
    mov edi, 2
    mov esi, 1
    xor edx, edx
    syscall
    test eax, eax
    js .net_listen_err
    mov ebx, eax                ; ebx = listen fd

    ; setsockopt(sockfd, SOL_SOCKET=1, SO_REUSEADDR=2, &one, 4)
    sub rsp, 16                 ; scratch space
    mov dword [rsp], 1          ; int one = 1
    mov eax, 54
    mov edi, ebx
    mov esi, 1                  ; SOL_SOCKET
    mov edx, 2                  ; SO_REUSEADDR
    lea r10, [rsp]
    mov r8d, 4
    syscall

    ; build sockaddr_in on stack: family(2) + port + INADDR_ANY + pad
    mov word [rsp], 2           ; sin_family = AF_INET
    mov word [rsp + 2], r12w    ; sin_port (already network order)
    mov dword [rsp + 4], 0      ; sin_addr = INADDR_ANY
    mov qword [rsp + 8], 0      ; padding

    ; bind(sockfd, &addr, 16)
    mov eax, 49
    mov edi, ebx
    lea rsi, [rsp]
    mov edx, 16
    syscall
    test eax, eax
    js .net_listen_close

    ; listen(sockfd, 1)
    mov eax, 50
    mov edi, ebx
    mov esi, 1
    syscall
    test eax, eax
    js .net_listen_close

    ; accept(sockfd, NULL, NULL)
    mov eax, 43
    mov edi, ebx
    xor esi, esi
    xor edx, edx
    syscall
    mov r12d, eax               ; save accepted fd
    test eax, eax
    js .net_listen_close

    ; close(listen_fd)
    mov eax, 3
    mov edi, ebx
    syscall

    add rsp, 16
    mov eax, r12d               ; return accepted fd
    pop r12
    pop rbx
    ret

.net_listen_close:
    mov r12d, eax               ; save error
    mov eax, 3
    mov edi, ebx
    syscall
    add rsp, 16
    mov eax, r12d
    pop r12
    pop rbx
    ret

.net_listen_err:
    pop r12
    pop rbx
    ret

; ============================================================================
; net_connect - connect to remote host
; Input:  edi = host IP (network byte order, 32-bit)
;         si  = port (network byte order, 16-bit)
; Output: rax = connected socket fd (negative on error)
; ============================================================================
net_connect:
    push rbx
    push r12
    push r13
    mov r12d, edi               ; save host
    movzx r13d, si              ; save port

    ; socket(AF_INET=2, SOCK_STREAM=1, 0)
    mov eax, 41
    mov edi, 2
    mov esi, 1
    xor edx, edx
    syscall
    test eax, eax
    js .net_connect_err
    mov ebx, eax                ; ebx = sockfd

    ; build sockaddr_in on stack
    sub rsp, 16
    mov word [rsp], 2           ; sin_family = AF_INET
    mov word [rsp + 2], r13w    ; sin_port
    mov dword [rsp + 4], r12d   ; sin_addr
    mov qword [rsp + 8], 0      ; padding

    ; connect(sockfd, &addr, 16)
    mov eax, 42
    mov edi, ebx
    lea rsi, [rsp]
    mov edx, 16
    syscall
    add rsp, 16
    test eax, eax
    js .net_connect_close

    mov eax, ebx                ; return sockfd
    pop r13
    pop r12
    pop rbx
    ret

.net_connect_close:
    mov r12d, eax               ; save error
    mov eax, 3
    mov edi, ebx
    syscall
    mov eax, r12d
    pop r13
    pop r12
    pop rbx
    ret

.net_connect_err:
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================================
; send_all - send exactly n bytes (handles partial writes)
; Input:  edi = fd, rsi = buffer, rdx = length
; Output: rax = 0 on success, -1 on error
; ============================================================================
send_all:
    push rbx
    push r12
    push r13
    push r14
    mov ebx, edi                ; fd
    mov r12, rsi                ; buffer
    mov r13, rdx                ; total length
    xor r14d, r14d              ; bytes sent so far

.send_all_loop:
    cmp r14, r13
    jge .send_all_done

    mov eax, 1                  ; sys_write
    mov edi, ebx
    lea rsi, [r12 + r14]
    mov rdx, r13
    sub rdx, r14
    syscall
    test rax, rax
    js .send_all_fail
    add r14, rax
    jmp .send_all_loop

.send_all_done:
    xor eax, eax
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.send_all_fail:
    mov rax, -1
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

; ============================================================================
; recv_exact - receive exactly n bytes (handles partial reads)
; Input:  edi = fd, rsi = buffer, rdx = length
; Output: rax = 0 on success, -1 on error/EOF
; ============================================================================
recv_exact:
    push rbx
    push r12
    push r13
    push r14
    mov ebx, edi                ; fd
    mov r12, rsi                ; buffer
    mov r13, rdx                ; total length
    xor r14d, r14d              ; bytes received so far

.recv_exact_loop:
    cmp r14, r13
    jge .recv_exact_done

    mov eax, 0                  ; sys_read
    mov edi, ebx
    lea rsi, [r12 + r14]
    mov rdx, r13
    sub rdx, r14
    syscall
    test rax, rax
    js .recv_exact_fail         ; error
    jz .recv_exact_fail         ; EOF
    add r14, rax
    jmp .recv_exact_loop

.recv_exact_done:
    xor eax, eax
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.recv_exact_fail:
    mov rax, -1
    pop r14
    pop r13
    pop r12
    pop rbx
    ret
