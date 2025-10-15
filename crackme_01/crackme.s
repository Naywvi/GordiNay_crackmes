;   
; ENCRYPT_THIS v1.0 - VERSION OBFUSQUÉE
;   
; Find the flag
; Techniques: Junk code, Opaque predicates, Dead code
;   nasm -f elf64 crackme.s -o crackme.o
;   ld crackme.o -o trust_yourself
; 

BITS 64

section .data
    banner db 0x48, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x48, 0x62, 0x62, 0x07
           db 0x0C, 0x01, 0x10, 0x1B, 0x12, 0x16, 0x1D, 0x16, 0x0A, 0x0B, 0x11, 0x62, 0x34, 0x73, 0x6C, 0x72, 0x48, 0x7F, 0x7F, 0x7F
           db 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x48, 0
    banner_len equ $ - banner
    
    prompt_user db 0x55^0x42, 0x73^0x42, 0x65^0x42, 0x72^0x42, 0x49^0x42
                db 0x44^0x42, 0x3A^0x42, 0x20^0x42, 0
    prompt_user_len equ $ - prompt_user
    
    prompt_serial db 0x4B^0x42, 0x65^0x42, 0x79^0x42, 0x3A^0x42, 0x20^0x42, 0
    prompt_serial_len equ $ - prompt_serial
    
    ; "Good Job!\n" pour le concours
    msg_success_competition db 71,111,111,100,32,74,111,98,33,10,0
    msg_success_competition_len equ $ - msg_success_competition
    
    ; "Bad Password!\n" pour le concours
    msg_fail_competition db 66,97,100,32,80,97,115,115,119,111,114,100,33,10,0
    msg_fail_competition_len equ $ - msg_fail_competition
    
    ; Messages originaux (chiffrés)
    msg_success db 0x0A^0x42, 0x5B^0x42, 0x4F^0x42, 0x4B^0x42, 0x5D^0x42
                db 0x20^0x42, 0x44^0x42, 0x65^0x42, 0x63^0x42, 0x72^0x42
                db 0x79^0x42, 0x70^0x42, 0x74^0x42, 0x65^0x42, 0x64^0x42
                db 0x21^0x42, 0x20^0x42, 0x46^0x42, 0x6C^0x42, 0x61^0x42
                db 0x67^0x42, 0x3A^0x42, 0x20^0x42, 0
    msg_success_len equ $ - msg_success
    
    msg_fail db 0x0A^0x42, 0x5B^0x42, 0x58^0x42, 0x5D^0x42, 0x20^0x42
             db 0x49^0x42, 0x6E^0x42, 0x76^0x42, 0x61^0x42, 0x6C^0x42
             db 0x69^0x42, 0x64^0x42, 0x20^0x42, 0x6B^0x42, 0x65^0x42
             db 0x79^0x42, 0x21^0x42, 0x0A^0x42, 0
    msg_fail_len equ $ - msg_fail
    
    ; Flag: "flag{_Ta-qwa_H=}" (16 chars) XOR 0x42
    flag_enc db 0x24, 0x2E, 0x23, 0x25, 0x39, 0x1D, 0x16, 0x23, 0x6F, 0x33, 0x35, 0x23, 0x1D, 0x0A, 0x7F, 0x3F, 0
    flag_len equ $ - flag_enc
    
    xor_key_1 dd 0x13371337
    xor_key_2 dd 0xDEADBEEF
    xor_key_3 dd 0xCAFEBABE
    
    padding_1 dq 0xAAAAAAAABBBBBBBB
    padding_2 dq 0xCCCCCCCCDDDDDDDD

section .bss
    input_buf_1 resb 64
    input_buf_2 resb 64
    hash_result resb 64
    temp_storage resb 128
    pipe_mode resb 1        ; 1 = mode pipe, 0 = mode interactif
    username_hash resb 8    ; Pour stocker le hash du username

section .text
    global _start

%macro JUNK_OPS 0
    push rax
    push rbx
    mov rax, 0xDEADBEEFCAFEBABE
    mov rbx, 0x1337133713371337
    xor rax, rbx
    rol rax, 13
    ror rax, 13
    add rax, 0
    sub rax, 0
    pop rbx
    pop rax
%endmacro

%macro OPAQUE_JMP 0
    nop
    nop
    nop
%endmacro

%macro FAKE_CALL 0
    nop
    nop
%endmacro

_start:
    push rbp
    mov rbp, rsp
    
    JUNK_OPS
    
    xor r10, r10
    test r10, r10
    jnz .dead_code_1
    jmp .real_entry
    
.dead_code_1:
    int3
    xor rax, rax
    div rax
    
.real_entry:
    JUNK_OPS
    
    ; Détecter si stdin est un pipe
    call detect_pipe_mode
    
    cmp byte [rel pipe_mode], 1
    je .pipe_mode
    
    ; Mode interactif
    call decrypt_and_print_banner
    OPAQUE_JMP
    call get_username
    FAKE_CALL
    call get_serial
    JUNK_OPS
    OPAQUE_JMP
    call compute_expected_serial
    jmp .do_check
    
.pipe_mode:
    ; Mode pipe (pour le concours)
    call read_flag_from_stdin
    
.do_check:
    mov r12, 0xABCD
    cmp r12, 0xABCD
    jne .dead_code_2
    jmp .check_flag
    
.dead_code_2:
    int3
    ret
    
.check_flag:
    cmp byte [rel pipe_mode], 1
    je .pipe_compare
    
    ; Mode interactif: comparer les serials
    call compare_serials
    jmp .check_result
    
.pipe_compare:
    ; Mode pipe: comparer directement le flag
    call compare_flag_direct
    
.check_result:
    xor rax, 1
    test rax, rax
    jz .success
    xor rax, 1
    test rax, rax
    jnz .fail
    
.fail:
    JUNK_OPS
    cmp byte [rel pipe_mode], 1
    je .fail_pipe
    call print_fail
    jmp .exit_fail
    
.fail_pipe:
    call print_fail_competition
    jmp .exit_fail
    
.success:
    OPAQUE_JMP
    cmp byte [rel pipe_mode], 1
    je .success_pipe
    call print_success
    JUNK_OPS
    call print_flag
    jmp .exit_success
    
.success_pipe:
    call print_success_competition
    jmp .exit_success
    
.exit_fail:
    mov rdi, 1
    mov rax, 60
    syscall
    
.exit_success:
    xor rdi, rdi
    mov rax, 60
    syscall

detect_pipe_mode:
    push rbp
    mov rbp, rsp
    push rbx
    
    ; Tester si stdin est un terminal (isatty)
    mov rax, 16          ; sys_ioctl
    xor rdi, rdi         ; stdin
    mov rsi, 0x5401      ; TCGETS
    lea rdx, [rel temp_storage]
    syscall
    
    ; Si erreur (rax < 0), c'est un pipe
    test rax, rax
    js .is_pipe
    
    ; C'est un terminal
    mov byte [rel pipe_mode], 0
    jmp .done
    
.is_pipe:
    mov byte [rel pipe_mode], 1
    
.done:
    pop rbx
    pop rbp
    ret

read_flag_from_stdin:
    push rbp
    mov rbp, rsp
    
    JUNK_OPS
    
    xor rax, rax
    xor rdi, rdi
    lea rsi, [rel input_buf_2]
    mov rdx, 64
    syscall
    
    mov rbx, rax
    
    test rbx, rbx
    jz .done
    lea rdi, [rel input_buf_2]
    add rdi, rbx
    dec rdi
    cmp byte [rdi], 0x0A
    jne .done
    mov byte [rdi], 0
    
.done:
    pop rbp
    ret

compare_flag_direct:
    push rbp
    mov rbp, rsp
    push rbx
    push rcx
    
    JUNK_OPS
    
    lea rsi, [rel input_buf_2]
    lea rdi, [rel flag_enc]
    mov rcx, 16             ; Exactement 16 caractères à comparer
    
.loop:
    movzx rax, byte [rsi]   ; Caractère de l'input
    movzx rbx, byte [rdi]   ; Caractère du flag chiffré
    
    ; Chiffrer le caractère de l'input avec XOR 0x42
    xor al, 0x42
    
    OPAQUE_JMP
    
    ; Comparer avec le flag chiffré stocké
    cmp al, bl
    jne .no_match
    
    inc rsi
    inc rdi
    dec rcx
    
    ; Continue jusqu'à avoir comparé les 16 caractères
    test rcx, rcx
    jnz .loop
    
    ; Vérifier qu'il n'y a pas de caractères supplémentaires dans l'input
    cmp byte [rsi], 0
    jne .no_match
    
.match:
    mov rax, 1
    xor rax, 0
    jmp .done
    
.no_match:
    xor rax, rax
    add rax, 0
    
.done:
    pop rcx
    pop rbx
    pop rbp
    ret

decrypt_and_print_banner:
    push rbp
    mov rbp, rsp
    push rbx
    push rcx
    push rsi
    
    JUNK_OPS
    
    lea rsi, [rel banner]
    mov bl, 0x42
    xor rcx, rcx
    
.decrypt_loop:
    mov al, [rsi + rcx]
    test al, al
    jz .done
    
    xor al, bl
    xor al, 0
    add al, 0
    
    mov [rsi + rcx], al
    inc rcx
    
    cmp rcx, -1
    je .dead_branch
    jmp .decrypt_loop
    
.dead_branch:
    int3
    
.done:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel banner]
    mov rdx, banner_len
    syscall
    
    pop rsi
    pop rcx
    pop rbx
    pop rbp
    ret

get_username:
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    
    JUNK_OPS
    
    lea rsi, [rel prompt_user]
    mov bl, 0x42
.decrypt:
    mov al, [rsi]
    test al, al
    jz .prompt
    xor al, bl
    mov [rsi], al
    inc rsi
    
    OPAQUE_JMP
    
    jmp .decrypt
    
.prompt:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel prompt_user]
    mov rdx, prompt_user_len
    syscall
    
    xor rax, rax
    xor rdi, rdi
    lea rsi, [rel input_buf_1]
    mov rdx, 64
    syscall
    
    mov rbx, rax
    
    JUNK_OPS
    
    test rbx, rbx
    jz .done
    lea rdi, [rel input_buf_1]
    add rdi, rbx
    dec rdi
    cmp byte [rdi], 0x0A
    jne .done
    mov byte [rdi], 0
    
.done:
    pop rsi
    pop rbx
    pop rbp
    ret

get_serial:
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    
    JUNK_OPS
    
    lea rsi, [rel prompt_serial]
    mov bl, 0x42
.decrypt:
    mov al, [rsi]
    test al, al
    jz .prompt
    xor al, bl
    mov [rsi], al
    inc rsi
    jmp .decrypt
    
.prompt:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel prompt_serial]
    mov rdx, prompt_serial_len
    syscall
    
    xor rax, rax
    xor rdi, rdi
    lea rsi, [rel input_buf_2]
    mov rdx, 64
    syscall
    
    mov rbx, rax
    
    OPAQUE_JMP
    
    test rbx, rbx
    jz .done
    lea rdi, [rel input_buf_2]
    add rdi, rbx
    dec rdi
    cmp byte [rdi], 0x0A
    jne .done
    mov byte [rdi], 0
    
.done:
    pop rsi
    pop rbx
    pop rbp
    ret

compute_expected_serial:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    
    JUNK_OPS
    
    mov r12d, [rel xor_key_1]
    xor r12, 0
    add r12, 0
    
    mov r13d, [rel xor_key_2]
    rol r13, 0
    
    mov r14d, [rel xor_key_3]
    ror r14, 0
    
    xor rax, rax
    xor rbx, rbx
    lea rsi, [rel input_buf_1]
    
    OPAQUE_JMP
    
.hash_loop:
    movzx rcx, byte [rsi + rbx]
    test rcx, rcx
    jz .hash_done
    
    imul rax, 33
    xor rax, 0
    xor rax, rcx
    
    JUNK_OPS
    
    rol rax, 7
    xor rax, r12
    
    inc rbx
    
    cmp rbx, -1
    je .dead
    jmp .hash_loop
    
.dead:
    int3
    
.hash_done:
    JUNK_OPS
    
    xor rax, r13
    mov rcx, rax
    rol rcx, 13
    xor rax, rcx
    xor rax, r14
    
    and eax, 0xFFFFFFFF
    
    OPAQUE_JMP
    
    lea rdi, [rel hash_result]
    call hex_to_string
    
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

hex_to_string:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    
    mov r12, rax
    add rdi, 7
    mov r13, 8
    
.convert_loop:
    mov rax, r12
    and rax, 0x0F
    
    cmp al, 9
    jg .letter
    add al, '0'
    jmp .store
    
.letter:
    sub al, 10
    add al, 'A'
    
.store:
    mov [rdi], al
    dec rdi
    shr r12, 4
    
    dec r13
    jnz .convert_loop
    
    add rdi, 9
    mov byte [rdi], 0
    
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

compare_serials:
    push rbp
    mov rbp, rsp
    push rbx
    
    JUNK_OPS
    
    lea rsi, [rel input_buf_2]
    lea rdi, [rel hash_result]
    
.loop:
    movzx rax, byte [rsi]
    movzx rbx, byte [rdi]
    
    cmp al, 'a'
    jb .c1
    cmp al, 'z'
    ja .c1
    sub al, 32
    
.c1:
    cmp bl, 'a'
    jb .c2
    cmp bl, 'z'
    ja .c2
    sub bl, 32
    
.c2:
    OPAQUE_JMP
    
    cmp al, bl
    jne .no_match
    
    test al, al
    jz .match
    
    inc rsi
    inc rdi
    
    cmp rax, -1
    je .dead_cmp
    
    jmp .loop
    
.dead_cmp:
    int3
    
.match:
    mov rax, 1
    xor rax, 0
    jmp .done
    
.no_match:
    xor rax, rax
    add rax, 0
    
.done:
    pop rbx
    pop rbp
    ret

print_success:
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    
    JUNK_OPS
    
    lea rsi, [rel msg_success]
    mov bl, 0x42
.decrypt:
    mov al, [rsi]
    test al, al
    jz .print
    xor al, bl
    mov [rsi], al
    inc rsi
    jmp .decrypt
    
.print:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel msg_success]
    mov rdx, msg_success_len
    syscall
    
    pop rsi
    pop rbx
    pop rbp
    ret

print_fail:
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    
    JUNK_OPS
    
    lea rsi, [rel msg_fail]
    mov bl, 0x42
.decrypt:
    mov al, [rsi]
    test al, al
    jz .print
    xor al, bl
    mov [rsi], al
    inc rsi
    jmp .decrypt
    
.print:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel msg_fail]
    mov rdx, msg_fail_len
    syscall
    
    pop rsi
    pop rbx
    pop rbp
    ret

print_success_competition:
    push rbp
    mov rbp, rsp
    
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel msg_success_competition]
    mov rdx, msg_success_competition_len
    syscall
    
    pop rbp
    ret

print_fail_competition:
    push rbp
    mov rbp, rsp
    
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel msg_fail_competition]
    mov rdx, msg_fail_competition_len
    syscall
    
    pop rbp
    ret

print_flag:
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    
    JUNK_OPS
    OPAQUE_JMP
    
    lea rsi, [rel flag_enc]
    mov bl, 0x42
.decrypt:
    mov al, [rsi]
    test al, al
    jz .print
    xor al, bl
    mov [rsi], al
    inc rsi
    jmp .decrypt
    
.print:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel flag_enc]
    mov rdx, 16  ; Exactement 16 caractères (pas le \0)
    syscall
    
    ; Ajouter un newline
    push 10
    mov rax, 1
    mov rdi, 1
    mov rsi, rsp
    mov rdx, 1
    syscall
    add rsp, 8
    
    pop rsi
    pop rbx
    pop rbp
    ret
