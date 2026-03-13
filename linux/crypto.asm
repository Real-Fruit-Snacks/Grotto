; crypto.asm - Nonce generation and wire protocol encrypt/decrypt wrappers
; Included into main.asm — shares its section .text

; ============================================================================
; generate_nonce - Fill 12 bytes from /dev/urandom
; Input:  rdi = output buffer (12 bytes)
; Output: rax = 0 success, -1 error
; ============================================================================
generate_nonce:
    push rbx
    push r12
    mov r12, rdi                ; save output buffer

    ; open("/dev/urandom", O_RDONLY)
    mov eax, 2                  ; sys_open
    lea rdi, [rel urandom_path]
    xor esi, esi                ; O_RDONLY = 0
    xor edx, edx
    syscall
    test eax, eax
    js .gen_nonce_fail
    mov ebx, eax                ; ebx = fd

    ; read(fd, buf, 12)
    mov eax, 0                  ; sys_read
    mov edi, ebx
    mov rsi, r12
    mov edx, 12
    syscall
    push rax                    ; save read result

    ; close(fd)
    mov eax, 3                  ; sys_close
    mov edi, ebx
    syscall

    pop rax
    cmp rax, 12
    jne .gen_nonce_fail

    xor eax, eax               ; success
    pop r12
    pop rbx
    ret

.gen_nonce_fail:
    mov rax, -1
    pop r12
    pop rbx
    ret

; ============================================================================
; encrypt_message - Encrypt plaintext into wire protocol format
; Input:  rdi = plaintext, esi = plaintext_len, rdx = output buffer
; Output: rax = total wire message length
; Wire format: [4B LE length][12B nonce][ciphertext][16B tag]
; ============================================================================
encrypt_message:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi                ; plaintext
    mov r13d, esi               ; plaintext_len
    mov r14, rdx                ; output buffer

    ; Calculate payload_len = 12 + pt_len + 16
    lea r15d, [r13d + 28]       ; payload_len = pt_len + 12 + 16

    ; Write payload_len as 4-byte LE at output[0..3]
    mov [r14], r15d

    ; Generate nonce at output[4..15]
    lea rdi, [r14 + 4]
    call generate_nonce
    test rax, rax
    js .enc_msg_fail

    ; aead_encrypt(key=g_key, nonce=&output[4], plaintext, pt_len, &output[16])
    lea rdi, [rel g_key]        ; key
    lea rsi, [r14 + 4]          ; nonce
    mov rdx, r12                ; plaintext
    mov ecx, r13d               ; plaintext length
    xor ecx, ecx
    mov ecx, r13d
    lea r8, [r14 + 16]          ; output (ciphertext + tag)
    call aead_encrypt

    ; Return 4 + payload_len
    lea eax, [r15d + 4]

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

.enc_msg_fail:
    mov rax, -1
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

; ============================================================================
; decrypt_message - Decrypt wire protocol payload
; Input:  rdi = payload (starts at nonce, after 4B length already read)
;         esi = payload_len
;         rdx = output buffer
; Output: rax = plaintext length on success, -1 on MAC failure
; ============================================================================
decrypt_message:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi                ; payload pointer (starts at nonce)
    mov r13d, esi               ; payload_len
    mov r14, rdx                ; output buffer

    ; nonce = payload[0..11]
    ; ciphertext = payload[12..payload_len-17]
    ; tag = payload[payload_len-16..payload_len-1]
    ; ct_len = payload_len - 12 - 16 = payload_len - 28

    mov r15d, r13d
    sub r15d, 28                ; ct_len

    ; aead_decrypt(key=g_key, nonce=payload, ciphertext=payload+12,
    ;              ct_len, tag=payload+payload_len-16, output)
    lea rdi, [rel g_key]        ; key
    mov rsi, r12                ; nonce (first 12 bytes of payload)
    lea rdx, [r12 + 12]         ; ciphertext
    mov ecx, r15d               ; ct_len
    xor ecx, ecx
    mov ecx, r15d
    mov r8d, r13d
    sub r8d, 16
    lea r8, [r12 + r8]          ; tag = payload + payload_len - 16
    mov r9, r14                 ; output buffer
    call aead_decrypt

    ; aead_decrypt returns plaintext length or -1
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

section .rodata
    urandom_path: db "/dev/urandom", 0

section .text
