; io.asm - Threaded bidirectional encrypted relay for Windows x86-64
; Uses CreateThread + WaitForMultipleObjects instead of poll()

; Buffer sizes (must match Linux relay)
%define BUF_SIZE        65536
%define WIRE_BUF_SIZE   65568       ; 65536 + 32 (nonce + tag overhead)

; Thread context structure offsets (passed via lpParameter)
; We store the context in .bss as global state
; g_sockfd, g_local_read, g_local_write, g_key, r15 (api_table) are all globals

; ============================================================================
; relay_start - Create two threads and wait for either to finish
; Input:  rcx = socket, rdx = local_read handle, r8 = local_write handle
; Expects r15 = api_table pointer
; Stores socket in g_sockfd, handles in g_local_read/g_local_write
; ============================================================================
relay_start:
    push    rbx
    push    r12
    push    r13
    push    r14
    sub     rsp, 104                ; shadow + space for handle array + args

    ; Save parameters to globals
    mov     [rel g_sockfd], rcx
    mov     [rel g_local_read], rdx
    mov     [rel g_local_write], r8

    ; Create thread 1: socket -> local (decrypt direction)
    ; CreateThread(NULL, 262144, thread_sock_to_local, NULL, 0, NULL)
    xor     ecx, ecx                ; lpThreadAttributes = NULL
    mov     edx, 262144             ; dwStackSize = 256KB (for ~128KB buffers)
    lea     r8, [rel thread_sock_to_local]  ; lpStartAddress
    xor     r9d, r9d                ; lpParameter = NULL
    mov     qword [rsp + 32], 0     ; dwCreationFlags = 0
    mov     qword [rsp + 40], 0     ; lpThreadId = NULL
    call    [r15 + API_CreateThread * 8]
    test    rax, rax
    jz      .relay_exit
    mov     [rel g_thread1], rax
    mov     r12, rax                ; save thread1 handle

    ; Create thread 2: local -> socket (encrypt direction)
    xor     ecx, ecx
    mov     edx, 262144             ; dwStackSize = 256KB
    lea     r8, [rel thread_local_to_sock]
    xor     r9d, r9d
    mov     qword [rsp + 32], 0
    mov     qword [rsp + 40], 0
    call    [r15 + API_CreateThread * 8]
    test    rax, rax
    jz      .relay_exit
    mov     [rel g_thread2], rax
    mov     r13, rax                ; save thread2 handle

    ; WaitForMultipleObjects(2, handles, FALSE, INFINITE)
    ; Build handle array on stack
    mov     [rsp + 64], r12         ; handles[0] = thread1
    mov     [rsp + 72], r13         ; handles[1] = thread2

    mov     ecx, 2                  ; nCount
    lea     rdx, [rsp + 64]         ; lpHandles
    xor     r8d, r8d                ; bWaitAll = FALSE
    mov     r9d, 0xFFFFFFFF         ; dwMilliseconds = INFINITE
    call    [r15 + API_WaitForMultipleObjects * 8]

    ; One thread exited — clean up both thread handles
    mov     rcx, r12
    call    [r15 + API_CloseHandle * 8]
    mov     rcx, r13
    call    [r15 + API_CloseHandle * 8]

.relay_exit:
    add     rsp, 104
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    jmp     cleanup_and_exit

; ============================================================================
; thread_sock_to_local - Thread entry: recv from socket, decrypt, write local
; LPTHREAD_START_ROUTINE: rcx = lpParameter (unused)
; Returns DWORD in eax
; ============================================================================
thread_sock_to_local:
    push    rbx
    push    rbp
    push    rdi
    push    rsi
    push    r12
    push    r13
    push    r14
    push    r15

    ; Restore r15 from global api_table
    lea     r15, [rel api_table]

    ; Allocate buffers on stack
    ; [rsp+0..3]          = length header (4 bytes)
    ; [rsp+16..WIRE]      = recv buffer
    ; [rsp+16+WIRE..]     = plaintext buffer
    ; [rsp+16+WIRE+BUF..] = bytes_written scratch (4 bytes)
    %define S2L_LENHDR      0
    %define S2L_RECVBUF     16
    %define S2L_PLAINBUF    (16 + WIRE_BUF_SIZE)
    %define S2L_WRITTEN     (16 + WIRE_BUF_SIZE + BUF_SIZE)
    %define S2L_TOTAL       (16 + WIRE_BUF_SIZE + BUF_SIZE + 16)

    sub     rsp, S2L_TOTAL
    ; Ensure 16-byte alignment (we pushed 8 regs = 64 bytes + return addr = 72)
    ; 72 + S2L_TOTAL should be 16-aligned; adjust if needed
    sub     rsp, 8                  ; alignment padding

.s2l_loop:
    ; Read 4-byte length header from socket
    mov     rcx, [rel g_sockfd]
    lea     rdx, [rsp + S2L_LENHDR + 8]  ; +8 for alignment padding
    mov     r8, 4
    call    recv_exact
    test    rax, rax
    jnz     .s2l_exit

    ; Get payload length (LE 32-bit)
    mov     ebp, [rsp + S2L_LENHDR + 8]

    ; Validate: must be >= 29 and <= 65536
    cmp     ebp, 29
    jb      .s2l_exit
    cmp     ebp, 65536
    ja      .s2l_exit

    ; Read payload into recv buffer
    mov     rcx, [rel g_sockfd]
    lea     rdx, [rsp + S2L_RECVBUF + 8]
    mov     r8d, ebp
    call    recv_exact
    test    rax, rax
    jnz     .s2l_exit

    ; Decrypt: decrypt_message(recv_buf, payload_len, plaintext_buf)
    ; System V convention: rdi, rsi, rdx
    lea     rdi, [rsp + S2L_RECVBUF + 8]
    mov     esi, ebp
    lea     rdx, [rsp + S2L_PLAINBUF + 8]
    call    decrypt_message
    cmp     rax, -1
    je      .s2l_exit

    mov     r12, rax                ; plaintext length

    ; WriteFile(local_write, plaintext, pt_len, &written, NULL)
    mov     rcx, [rel g_local_write]
    lea     rdx, [rsp + S2L_PLAINBUF + 8]
    mov     r8d, r12d
    lea     r9, [rsp + S2L_WRITTEN + 8]
    mov     qword [rsp + 32], 0         ; lpOverlapped = NULL
    call    [r15 + API_WriteFile * 8]
    test    eax, eax
    jz      .s2l_exit               ; WriteFile failed

    jmp     .s2l_loop

.s2l_exit:
    add     rsp, S2L_TOTAL + 8
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rsi
    pop     rdi
    pop     rbp
    pop     rbx
    xor     eax, eax                ; return 0
    ret

; ============================================================================
; thread_local_to_sock - Thread entry: read from local, encrypt, send to socket
; LPTHREAD_START_ROUTINE: rcx = lpParameter (unused)
; Returns DWORD in eax
; ============================================================================
thread_local_to_sock:
    push    rbx
    push    rbp
    push    rdi
    push    rsi
    push    r12
    push    r13
    push    r14
    push    r15

    lea     r15, [rel api_table]

    ; Stack buffers:
    ; [rsp+0..BUF-1]        = plaintext read buffer
    ; [rsp+BUF..BUF+WIRE-1] = send buffer (encrypted)
    ; [rsp+BUF+WIRE..]      = bytes_read scratch (4 bytes)
    %define L2S_PLAINBUF    0
    %define L2S_SENDBUF     BUF_SIZE
    %define L2S_BYTESREAD   (BUF_SIZE + WIRE_BUF_SIZE)
    %define L2S_TOTAL       (BUF_SIZE + WIRE_BUF_SIZE + 16)

    sub     rsp, L2S_TOTAL
    sub     rsp, 8                  ; alignment padding

.l2s_loop:
    ; ReadFile(local_read, plaintext_buf, BUF_SIZE, &bytes_read, NULL)
    mov     rcx, [rel g_local_read]
    lea     rdx, [rsp + L2S_PLAINBUF + 8]
    mov     r8d, BUF_SIZE
    lea     r9, [rsp + L2S_BYTESREAD + 8]
    mov     qword [rsp + 32], 0         ; lpOverlapped = NULL
    call    [r15 + API_ReadFile * 8]
    test    eax, eax
    jz      .l2s_exit               ; ReadFile failed or EOF

    mov     r12d, [rsp + L2S_BYTESREAD + 8]  ; bytes actually read
    test    r12d, r12d
    jz      .l2s_exit               ; 0 bytes = EOF

    ; Encrypt: encrypt_message(plaintext, bytes_read, send_buf)
    ; System V convention: rdi, esi, rdx
    lea     rdi, [rsp + L2S_PLAINBUF + 8]
    mov     esi, r12d
    lea     rdx, [rsp + L2S_SENDBUF + 8]
    call    encrypt_message
    cmp     rax, -1
    je      .l2s_exit

    mov     r12, rax                ; total wire length

    ; send_all(socket, send_buf, wire_len)
    ; Windows convention: rcx, rdx, r8
    mov     rcx, [rel g_sockfd]
    lea     rdx, [rsp + L2S_SENDBUF + 8]
    mov     r8, r12
    call    send_all
    test    rax, rax
    jnz     .l2s_exit

    jmp     .l2s_loop

.l2s_exit:
    add     rsp, L2S_TOTAL + 8
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rsi
    pop     rdi
    pop     rbp
    pop     rbx
    xor     eax, eax
    ret
