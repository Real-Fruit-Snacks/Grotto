; crypto.asm - Nonce generation and wire protocol encrypt/decrypt wrappers
; Windows version: uses SystemFunction036 (RtlGenRandom) for nonce generation
; Calls shared aead.inc functions using System V calling convention

; ============================================================================
; generate_nonce - Fill 12 bytes using RtlGenRandom (SystemFunction036)
; Input:  rcx = output buffer (12 bytes)
; Output: rax = 0 success, -1 error
; Expects r15 = api_table pointer
; ============================================================================
generate_nonce:
    push    rbx
    sub     rsp, 32                 ; shadow space

    mov     rbx, rcx                ; save output buffer

    ; SystemFunction036(buf, len) - Windows calling convention
    mov     rcx, rbx
    mov     edx, 12
    call    [r15 + API_SystemFunction036 * 8]
    ; Returns nonzero (TRUE) on success
    test    eax, eax
    jz      .gen_nonce_fail

    xor     eax, eax                ; success = 0
    add     rsp, 32
    pop     rbx
    ret

.gen_nonce_fail:
    mov     rax, -1
    add     rsp, 32
    pop     rbx
    ret

; ============================================================================
; encrypt_message - Encrypt plaintext into wire protocol format
; Input:  rdi = plaintext, esi = plaintext_len, rdx = output buffer
;         (System V convention to match relay code pattern)
; Output: rax = total wire message length, -1 on error
; Wire format: [4B LE length][12B nonce][ciphertext][16B tag]
; Expects r15 = api_table pointer, g_key accessible
; ============================================================================
encrypt_message:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14
    ; r15 preserved as api_table pointer (callee-saved)

    mov     r12, rdi                ; plaintext
    mov     r13d, esi               ; plaintext_len
    mov     r14, rdx                ; output buffer

    ; payload_len = 12 + pt_len + 16 = pt_len + 28
    lea     ebp, [r13d + 28]        ; rbp = payload_len

    ; Write payload_len as 4-byte LE at output[0..3]
    mov     [r14], ebp

    ; Generate nonce at output[4..15] using Windows convention
    lea     rcx, [r14 + 4]
    call    generate_nonce
    test    rax, rax
    js      .enc_msg_fail

    ; aead_encrypt(key=g_key, nonce=&output[4], plaintext, pt_len, &output[16])
    ; System V calling convention: rdi, rsi, rdx, rcx, r8
    lea     rdi, [rel g_key]        ; key
    lea     rsi, [r14 + 4]          ; nonce
    mov     rdx, r12                ; plaintext
    xor     ecx, ecx
    mov     ecx, r13d               ; plaintext length
    lea     r8, [r14 + 16]          ; output (ciphertext + tag)
    call    aead_encrypt

    ; Return 4 + payload_len
    lea     eax, [ebp + 4]

    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret

.enc_msg_fail:
    mov     rax, -1
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret

; ============================================================================
; decrypt_message - Decrypt wire protocol payload
; Input:  rdi = payload (starts at nonce, after 4B length already read)
;         esi = payload_len
;         rdx = output buffer
; Output: rax = plaintext length on success, -1 on MAC failure
; ============================================================================
decrypt_message:
    push    rbx
    push    rbp
    push    r12
    push    r13
    push    r14

    mov     r12, rdi                ; payload pointer (starts at nonce)
    mov     r13d, esi               ; payload_len
    mov     r14, rdx                ; output buffer

    ; ct_len = payload_len - 28
    mov     ebp, r13d
    sub     ebp, 28                 ; ebp = ct_len

    ; aead_decrypt(key=g_key, nonce=payload, ct=payload+12,
    ;              ct_len, tag=payload+payload_len-16, output)
    ; System V calling convention: rdi, rsi, rdx, rcx, r8, r9
    lea     rdi, [rel g_key]        ; key
    mov     rsi, r12                ; nonce (first 12 bytes of payload)
    lea     rdx, [r12 + 12]         ; ciphertext
    xor     ecx, ecx
    mov     ecx, ebp                ; ct_len
    mov     r8d, r13d
    sub     r8d, 16
    lea     r8, [r12 + r8]          ; tag = payload + payload_len - 16
    mov     r9, r14                 ; output buffer
    call    aead_decrypt

    ; aead_decrypt returns plaintext length or -1
    pop     r14
    pop     r13
    pop     r12
    pop     rbp
    pop     rbx
    ret
