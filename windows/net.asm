; net.asm - Windows x86-64 networking via ws2_32.dll
; All calls through api_table[r15] using Windows x64 calling convention

; ============================================================================
; net_init - Initialize Winsock
; Expects r15 = api_table pointer
; Output: rax = 0 on success, nonzero on error
; ============================================================================
net_init:
    push    rbx
    sub     rsp, 0x1C0              ; WSADATA is 408 bytes; round up + shadow

    ; WSAStartup(0x0202, &wsadata)
    mov     ecx, 0x0202             ; wVersionRequested = 2.2
    lea     rdx, [rsp + 32]         ; lpWSAData
    call    [r15 + API_WSAStartup * 8]
    ; rax = 0 on success

    add     rsp, 0x1C0
    pop     rbx
    ret

; ============================================================================
; net_listen - Bind, listen, accept one TCP connection
; Input:  cx = port (network byte order, 16-bit)
; Output: rax = accepted socket (INVALID_SOCKET on error)
; Expects r15 = api_table pointer
; ============================================================================
net_listen:
    push    rbx
    push    r12
    push    r13
    push    r14
    sub     rsp, 104                ; shadow + sockaddr_in + scratch (aligned)

    movzx   r12d, cx                ; save port

    ; socket(AF_INET=2, SOCK_STREAM=1, IPPROTO_TCP=6)
    mov     ecx, 2                  ; AF_INET
    mov     edx, 1                  ; SOCK_STREAM
    mov     r8d, 6                  ; IPPROTO_TCP
    call    [r15 + API_socket * 8]
    cmp     rax, -1
    je      .listen_fail
    mov     rbx, rax                ; rbx = listen socket

    ; Build sockaddr_in at [rsp+32]
    mov     word [rsp + 32], 2      ; sin_family = AF_INET
    mov     word [rsp + 34], r12w   ; sin_port (network order)
    mov     dword [rsp + 36], 0     ; sin_addr = INADDR_ANY
    mov     qword [rsp + 40], 0     ; padding

    ; bind(sock, &addr, 16)
    mov     rcx, rbx
    lea     rdx, [rsp + 32]
    mov     r8d, 16
    call    [r15 + API_bind * 8]
    test    eax, eax
    jnz     .listen_close

    ; listen(sock, 1)
    mov     rcx, rbx
    mov     edx, 1
    call    [r15 + API_listen * 8]
    test    eax, eax
    jnz     .listen_close

    ; accept(sock, NULL, NULL)
    mov     rcx, rbx
    xor     edx, edx
    xor     r8d, r8d
    call    [r15 + API_accept * 8]
    cmp     rax, -1
    je      .listen_close
    mov     r13, rax                ; r13 = accepted socket

    ; closesocket(listen_sock)
    mov     rcx, rbx
    call    [r15 + API_closesocket * 8]

    mov     rax, r13                ; return accepted socket

    add     rsp, 104
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret

.listen_close:
    mov     rcx, rbx
    call    [r15 + API_closesocket * 8]
.listen_fail:
    mov     rax, -1
    add     rsp, 104
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret

; ============================================================================
; net_connect - Connect to a remote host
; Input:  ecx = host IP (network byte order), dx = port (network byte order)
; Output: rax = connected socket (INVALID_SOCKET=-1 on error)
; Expects r15 = api_table pointer
; ============================================================================
net_connect:
    push    rbx
    push    r12
    push    r13
    sub     rsp, 80                 ; shadow + sockaddr_in + scratch

    mov     r12d, ecx               ; save host
    movzx   r13d, dx                ; save port

    ; socket(AF_INET=2, SOCK_STREAM=1, IPPROTO_TCP=6)
    mov     ecx, 2
    mov     edx, 1
    mov     r8d, 6
    call    [r15 + API_socket * 8]
    cmp     rax, -1
    je      .connect_fail
    mov     rbx, rax                ; rbx = socket

    ; Build sockaddr_in at [rsp+32]
    mov     word [rsp + 32], 2      ; sin_family = AF_INET
    mov     word [rsp + 34], r13w   ; sin_port
    mov     dword [rsp + 36], r12d  ; sin_addr
    mov     qword [rsp + 40], 0     ; padding

    ; connect(sock, &addr, 16)
    mov     rcx, rbx
    lea     rdx, [rsp + 32]
    mov     r8d, 16
    call    [r15 + API_connect * 8]
    test    eax, eax
    jnz     .connect_close

    mov     rax, rbx                ; return socket
    add     rsp, 80
    pop     r13
    pop     r12
    pop     rbx
    ret

.connect_close:
    mov     rcx, rbx
    call    [r15 + API_closesocket * 8]
.connect_fail:
    mov     rax, -1
    add     rsp, 80
    pop     r13
    pop     r12
    pop     rbx
    ret

; ============================================================================
; send_all - Send exactly n bytes (handles partial writes)
; Input:  rcx = socket, rdx = buffer, r8 = length
; Output: rax = 0 on success, -1 on error
; Expects r15 = api_table pointer
; ============================================================================
send_all:
    push    rbx
    push    r12
    push    r13
    push    r14
    sub     rsp, 40                 ; shadow space (aligned)

    mov     rbx, rcx                ; socket
    mov     r12, rdx                ; buffer
    mov     r13, r8                 ; total length
    xor     r14d, r14d              ; bytes sent so far

.send_loop:
    cmp     r14, r13
    jge     .send_done

    ; send(sock, buf+offset, remaining, 0)
    mov     rcx, rbx
    lea     rdx, [r12 + r14]
    mov     r8, r13
    sub     r8, r14
    xor     r9d, r9d                ; flags = 0
    call    [r15 + API_send * 8]
    cmp     eax, -1
    je      .send_fail
    movsx   rax, eax                ; sign-extend
    add     r14, rax
    jmp     .send_loop

.send_done:
    xor     eax, eax
    add     rsp, 40
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret

.send_fail:
    mov     rax, -1
    add     rsp, 40
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret

; ============================================================================
; recv_exact - Receive exactly n bytes (handles partial reads)
; Input:  rcx = socket, rdx = buffer, r8 = length
; Output: rax = 0 on success, -1 on error/EOF
; Expects r15 = api_table pointer
; ============================================================================
recv_exact:
    push    rbx
    push    r12
    push    r13
    push    r14
    sub     rsp, 40                 ; shadow space (aligned)

    mov     rbx, rcx                ; socket
    mov     r12, rdx                ; buffer
    mov     r13, r8                 ; total length
    xor     r14d, r14d              ; bytes received so far

.recv_loop:
    cmp     r14, r13
    jge     .recv_done

    ; recv(sock, buf+offset, remaining, 0)
    mov     rcx, rbx
    lea     rdx, [r12 + r14]
    mov     r8, r13
    sub     r8, r14
    xor     r9d, r9d                ; flags = 0
    call    [r15 + API_recv * 8]
    cmp     eax, -1
    je      .recv_fail
    test    eax, eax
    jz      .recv_fail              ; EOF
    movsx   rax, eax                ; sign-extend
    add     r14, rax
    jmp     .recv_loop

.recv_done:
    xor     eax, eax
    add     rsp, 40
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret

.recv_fail:
    mov     rax, -1
    add     rsp, 40
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret
