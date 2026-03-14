; shell.asm - CreateProcessA with pipe redirection for Windows x86-64
; Expects r15 = api_table pointer

; STARTUPINFOA size = 104 bytes (0x68)
; PROCESS_INFORMATION size = 24 bytes (0x18)
; SECURITY_ATTRIBUTES size = 24 bytes (0x18)

; STARTF_USESTDHANDLES = 0x100
; HANDLE_FLAG_INHERIT = 0x01

; ============================================================================
; spawn_shell - Create child process with pipe redirection
; Input:  rcx = pointer to command string
; Output: rax = stdout_read handle, rdx = stdin_write handle,
;         r8 = process handle
;         rax = -1 on error
; Stores process handle in g_child_process
; Expects r15 = api_table pointer
; ============================================================================
spawn_shell:
    push    rbx
    push    rbp
    push    rdi
    push    rsi
    push    r12
    push    r13
    push    r14
    ; r15 = api_table (preserved)

    mov     r12, rcx                ; command string

    ; Stack layout (shadow + stack args at bottom for correct API offsets):
    ;   [rsp+0..31]   shadow space (32 bytes, used by all API calls)
    ;   [rsp+32..79]  stack args for CreateProcessA (6 x 8 = 48 bytes)
    ;   [rsp+80]      SECURITY_ATTRIBUTES (24 bytes)
    ;   [rsp+104]     stdin_read handle (8)
    ;   [rsp+112]     stdin_write handle (8)
    ;   [rsp+120]     stdout_read handle (8)
    ;   [rsp+128]     stdout_write handle (8)
    ;   [rsp+136]     STARTUPINFOA (104 bytes)
    ;   [rsp+240]     PROCESS_INFORMATION (24 bytes)
    ;   [rsp+264..271] alignment padding
    ;   Total: 272 bytes (7 pushes=56 + 272 = 328 ≡ 8 mod 16)
    %define SH_SECATTR      80
    %define SH_STDIN_RD     104
    %define SH_STDIN_WR     112
    %define SH_STDOUT_RD    120
    %define SH_STDOUT_WR    128
    %define SH_STARTUPINFO  136
    %define SH_PROCINFO     240
    %define SH_TOTAL        272

    sub     rsp, SH_TOTAL

    ; Zero out STARTUPINFOA
    lea     rdi, [rsp + SH_STARTUPINFO]
    xor     eax, eax
    mov     ecx, 104
.zero_si:
    mov     byte [rdi + rcx - 1], 0
    dec     ecx
    jnz     .zero_si

    ; Zero out PROCESS_INFORMATION
    mov     qword [rsp + SH_PROCINFO], 0
    mov     qword [rsp + SH_PROCINFO + 8], 0
    mov     qword [rsp + SH_PROCINFO + 16], 0

    ; Set up SECURITY_ATTRIBUTES for inheritable handles
    mov     dword [rsp + SH_SECATTR], 24        ; nLength
    mov     qword [rsp + SH_SECATTR + 8], 0     ; lpSecurityDescriptor = NULL
    mov     dword [rsp + SH_SECATTR + 16], 1    ; bInheritHandle = TRUE

    ; CreatePipe(&stdin_read, &stdin_write, &sa, 0)
    lea     rcx, [rsp + SH_STDIN_RD]
    lea     rdx, [rsp + SH_STDIN_WR]
    lea     r8, [rsp + SH_SECATTR]
    xor     r9d, r9d                ; nSize = 0 (default)
    call    [r15 + API_CreatePipe * 8]
    test    eax, eax
    jz      .spawn_fail

    ; CreatePipe(&stdout_read, &stdout_write, &sa, 0)
    lea     rcx, [rsp + SH_STDOUT_RD]
    lea     rdx, [rsp + SH_STDOUT_WR]
    lea     r8, [rsp + SH_SECATTR]
    xor     r9d, r9d
    call    [r15 + API_CreatePipe * 8]
    test    eax, eax
    jz      .spawn_close_stdin

    ; SetHandleInformation on parent-side handles (not inherited by child)
    ; stdin_write: clear HANDLE_FLAG_INHERIT
    mov     rcx, [rsp + SH_STDIN_WR]
    mov     edx, 1                  ; HANDLE_FLAG_INHERIT
    xor     r8d, r8d                ; flags = 0 (clear inherit)
    call    [r15 + API_SetHandleInformation * 8]

    ; stdout_read: clear HANDLE_FLAG_INHERIT
    mov     rcx, [rsp + SH_STDOUT_RD]
    mov     edx, 1                  ; HANDLE_FLAG_INHERIT
    xor     r8d, r8d
    call    [r15 + API_SetHandleInformation * 8]

    ; Set up STARTUPINFOA
    mov     dword [rsp + SH_STARTUPINFO], 104       ; cb = sizeof(STARTUPINFOA)
    mov     dword [rsp + SH_STARTUPINFO + 60], 0x100 ; dwFlags = STARTF_USESTDHANDLES

    ; hStdInput = stdin_read (child reads from this)
    mov     rax, [rsp + SH_STDIN_RD]
    mov     [rsp + SH_STARTUPINFO + 80], rax        ; hStdInput

    ; hStdOutput = stdout_write (child writes to this)
    mov     rax, [rsp + SH_STDOUT_WR]
    mov     [rsp + SH_STARTUPINFO + 88], rax        ; hStdOutput

    ; hStdError = stdout_write (child writes stderr here too)
    mov     [rsp + SH_STARTUPINFO + 96], rax        ; hStdError

    ; CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)
    ; 10 args: 4 in registers, 6 on stack at [rsp+32..72]
    xor     ecx, ecx                ; lpApplicationName = NULL
    mov     rdx, r12                ; lpCommandLine
    xor     r8d, r8d                ; lpProcessAttributes = NULL
    xor     r9d, r9d                ; lpThreadAttributes = NULL
    mov     dword [rsp + 32], 1     ; bInheritHandles = TRUE
    mov     qword [rsp + 40], 0     ; dwCreationFlags = 0
    mov     qword [rsp + 48], 0     ; lpEnvironment = NULL
    mov     qword [rsp + 56], 0     ; lpCurrentDirectory = NULL
    lea     rax, [rsp + SH_STARTUPINFO]
    mov     [rsp + 64], rax         ; lpStartupInfo
    lea     rax, [rsp + SH_PROCINFO]
    mov     [rsp + 72], rax         ; lpProcessInformation
    call    [r15 + API_CreateProcessA * 8]
    test    eax, eax
    jz      .spawn_close_all

    ; Success — save process handle
    mov     rax, [rsp + SH_PROCINFO]         ; hProcess
    mov     [rel g_child_process], rax
    mov     r13, rax                          ; save process handle

    ; Close child-side pipe handles (parent doesn't need them)
    mov     rcx, [rsp + SH_STDIN_RD]
    call    [r15 + API_CloseHandle * 8]
    mov     rcx, [rsp + SH_STDOUT_WR]
    call    [r15 + API_CloseHandle * 8]

    ; Close thread handle (we don't need it)
    mov     rcx, [rsp + SH_PROCINFO + 8]     ; hThread
    call    [r15 + API_CloseHandle * 8]

    ; Return: rax = stdout_read, rdx = stdin_write, r8 = process handle
    mov     rax, [rsp + SH_STDOUT_RD]
    mov     rdx, [rsp + SH_STDIN_WR]
    mov     r8, r13

    add     rsp, SH_TOTAL
    pop     r14
    pop     r13
    pop     r12
    pop     rsi
    pop     rdi
    pop     rbp
    pop     rbx
    ret

.spawn_close_all:
    ; Close stdout pipe handles
    mov     rcx, [rsp + SH_STDOUT_RD]
    call    [r15 + API_CloseHandle * 8]
    mov     rcx, [rsp + SH_STDOUT_WR]
    call    [r15 + API_CloseHandle * 8]

.spawn_close_stdin:
    ; Close stdin pipe handles
    mov     rcx, [rsp + SH_STDIN_RD]
    call    [r15 + API_CloseHandle * 8]
    mov     rcx, [rsp + SH_STDIN_WR]
    call    [r15 + API_CloseHandle * 8]

.spawn_fail:
    mov     rax, -1
    add     rsp, SH_TOTAL
    pop     r14
    pop     r13
    pop     r12
    pop     rsi
    pop     rdi
    pop     rbp
    pop     rbx
    ret
