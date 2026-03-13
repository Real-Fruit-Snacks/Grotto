; shell.asm - Fork and exec with pipe redirection
; Included into main.asm — shares its section .text

; ============================================================================
; spawn_shell - Fork and exec command with pipe redirection
; Input:  rdi = pointer to command string
; Output: eax = read_fd (child stdout), edx = write_fd (child stdin)
;         eax = -1 on error
; Also stores child PID in g_child_pid
; ============================================================================
spawn_shell:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15

    mov r12, rdi                ; command string

    ; Allocate space for two pipes (4 ints = 16 bytes) + argv array (16 bytes)
    ; stdin_pipe[0..1] at [rsp+0]  (read, write)
    ; stdout_pipe[0..1] at [rsp+8] (read, write)
    ; argv at [rsp+16]: [cmd_ptr, NULL]
    sub rsp, 48

    ; pipe(stdin_pipe)  — syscall 22
    mov eax, 22
    lea rdi, [rsp]
    syscall
    test eax, eax
    js .spawn_fail

    ; pipe(stdout_pipe) — syscall 22
    mov eax, 22
    lea rdi, [rsp + 8]
    syscall
    test eax, eax
    js .spawn_fail

    ; fork() — syscall 57
    mov eax, 57
    syscall
    test rax, rax
    js .spawn_fail
    jz .child_process

    ; --- Parent process ---
    ; rax = child PID
    mov [rel g_child_pid], rax

    ; Close child's pipe ends: stdin_pipe[0] (child reads from), stdout_pipe[1] (child writes to)
    mov eax, 3                  ; sys_close
    mov edi, [rsp]              ; stdin_pipe[0]
    syscall

    mov eax, 3
    mov edi, [rsp + 12]         ; stdout_pipe[1]
    syscall

    ; Return: eax = stdout_pipe[0] (read child output), edx = stdin_pipe[1] (write to child)
    mov eax, [rsp + 8]          ; stdout_pipe[0]
    mov edx, [rsp + 4]          ; stdin_pipe[1]

    ; Also store write_fd for cleanup
    mov [rel g_shell_write_fd], edx

    add rsp, 48
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

.child_process:
    ; dup2(stdin_pipe[0], 0) — redirect stdin
    mov eax, 33                 ; sys_dup2
    mov edi, [rsp]              ; stdin_pipe[0]
    xor esi, esi                ; fd 0 = stdin
    syscall

    ; dup2(stdout_pipe[1], 1) — redirect stdout
    mov eax, 33
    mov edi, [rsp + 12]         ; stdout_pipe[1]
    mov esi, 1                  ; fd 1 = stdout
    syscall

    ; dup2(stdout_pipe[1], 2) — redirect stderr
    mov eax, 33
    mov edi, [rsp + 12]         ; stdout_pipe[1]
    mov esi, 2                  ; fd 2 = stderr
    syscall

    ; Close all 4 pipe fds
    mov eax, 3
    mov edi, [rsp]              ; stdin_pipe[0]
    syscall
    mov eax, 3
    mov edi, [rsp + 4]          ; stdin_pipe[1]
    syscall
    mov eax, 3
    mov edi, [rsp + 8]          ; stdout_pipe[0]
    syscall
    mov eax, 3
    mov edi, [rsp + 12]         ; stdout_pipe[1]
    syscall

    ; Set up argv = [cmd, NULL]
    mov [rsp + 16], r12         ; argv[0] = command
    mov qword [rsp + 24], 0     ; argv[1] = NULL

    ; execve(cmd, argv, NULL) — syscall 59
    mov eax, 59
    mov rdi, r12                ; filename
    lea rsi, [rsp + 16]         ; argv
    xor edx, edx                ; envp = NULL
    syscall

    ; If execve returns, it failed — exit(1)
    mov eax, 60
    mov edi, 1
    syscall

.spawn_fail:
    add rsp, 48
    mov eax, -1
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret
