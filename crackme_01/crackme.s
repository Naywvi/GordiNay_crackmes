;  
; CRACKME - "DO YOU TRUST YOUR SYSTEM?"

; Objectif : Trouver le bon serial pour le username
; Compilation :
;   nasm -f elf64 crackme.s -o crackme.o
;   ld crackme.o -o crackme
;  

BITS 64

section .data
    ; Nouvelle bannière stylée (XOR 0x42)
    banner db 0x0A, 0x7B^0x42, 0x21^0x42, 0x7D^0x42, 0x20^0x42
           db 0x44^0x42, 0x4F^0x42, 0x20^0x42, 0x59^0x42, 0x4F^0x42
           db 0x55^0x42, 0x20^0x42, 0x54^0x42, 0x52^0x42, 0x55^0x42
           db 0x53^0x42, 0x54^0x42, 0x20^0x42, 0x59^0x42, 0x4F^0x42
           db 0x55^0x42, 0x52^0x42, 0x20^0x42, 0x53^0x42, 0x59^0x42
           db 0x53^0x42, 0x54^0x42, 0x45^0x42, 0x4D^0x42, 0x3F^0x42
           db 0x20^0x42, 0x7B^0x42, 0x21^0x42, 0x7D^0x42
           db 0x0A^0x42, 0
    banner_len equ $ - banner
    
    prompt_user db 0x55^0x42, 0x73^0x42, 0x65^0x42, 0x72^0x42, 0x6E^0x42
                db 0x61^0x42, 0x6D^0x42, 0x65^0x42, 0x3A^0x42, 0x20^0x42, 0
    prompt_user_len equ $ - prompt_user
    
    prompt_serial db 0x53^0x42, 0x65^0x42, 0x72^0x42, 0x69^0x42, 0x61^0x42
                  db 0x6C^0x42, 0x3A^0x42, 0x20^0x42, 0
    prompt_serial_len equ $ - prompt_serial
    
    msg_success db 0x0A^0x42, 0x5B^0x42, 0x2B^0x42, 0x5D^0x42, 0x20^0x42
                db 0x41^0x42, 0x63^0x42, 0x63^0x42, 0x65^0x42, 0x73^0x42
                db 0x73^0x42, 0x20^0x42, 0x47^0x42, 0x72^0x42, 0x61^0x42
                db 0x6E^0x42, 0x74^0x42, 0x65^0x42, 0x64^0x42, 0x21^0x42
                db 0x20^0x42, 0x46^0x42, 0x6C^0x42, 0x61^0x42, 0x67^0x42
                db 0x3A^0x42, 0x20^0x42, 0
    msg_success_len equ $ - msg_success
    
    msg_fail db 0x0A^0x42, 0x5B^0x42, 0x2D^0x42, 0x5D^0x42, 0x20^0x42
             db 0x41^0x42, 0x63^0x42, 0x63^0x42, 0x65^0x42, 0x73^0x42
             db 0x73^0x42, 0x20^0x42, 0x44^0x42, 0x65^0x42, 0x6E^0x42
             db 0x69^0x42, 0x65^0x42, 0x64^0x42, 0x21^0x42, 0x0A^0x42, 0
    msg_fail_len equ $ - msg_fail
    
    ; Flag: flag{1_T4k1_Allah_}
    flag_enc db 0x66^0x42, 0x6C^0x42, 0x61^0x42, 0x67^0x42, 0x7B^0x42
             db 0x31^0x42, 0x5F^0x42, 0x54^0x42, 0x34^0x42, 0x6B^0x42
             db 0x31^0x42, 0x5F^0x42, 0x41^0x42, 0x6C^0x42, 0x6C^0x42
             db 0x61^0x42, 0x68^0x42, 0x5F^0x42, 0x7D^0x42
             db 0x0A^0x42, 0
    flag_len equ $ - flag_enc
    
    ;  algo constants
     algo1 dd 0x13371337
     algo2 dd 0xDEADBEEF
     algo3 dd 0xCAFEBABE

section .bss
    username resb 64
    serial resb 64
    computed_serial resb 64

section .text
    global _start

_start:
    push rbp
    mov rbp, rsp
    
    ; Afficher banner
    call decrypt_and_print_banner
    
    ; Demander username
    call get_username
    
    ; Demander serial
    call get_serial
    
    ; Calculer le serial attendu
    call compute_expected_serial
    
    ; Comparer
    call compare_serials
    cmp rax, 1
    je .success
    
.fail:
    call print_fail
    jmp .exit
    
.success:
    call print_success
    call print_flag
    
.exit:
    mov rax, 60
    xor rdi, rdi
    syscall

;  
; DÉCHIFFRER ET AFFICHER BANNER
;  
decrypt_and_print_banner:
    push rbp
    mov rbp, rsp
    
    lea rsi, [rel banner]
    mov bl, 0x42
    
.decrypt_loop:
    mov al, [rsi]
    test al, al
    jz .done
    xor al, bl
    mov [rsi], al
    inc rsi
    jmp .decrypt_loop
    
.done:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel banner]
    mov rdx, banner_len
    syscall
    
    pop rbp
    ret

;  
; OBTENIR USERNAME
;  
get_username:
    push rbp
    mov rbp, rsp
    push rbx
    
    ; Déchiffrer prompt
    lea rsi, [rel prompt_user]
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
    ; Afficher prompt
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel prompt_user]
    mov rdx, prompt_user_len
    syscall
    
    ; Lire input
    mov rax, 0
    mov rdi, 0
    lea rsi, [rel username]
    mov rdx, 64
    syscall
    
    ; Sauvegarder la longueur
    mov rbx, rax
    
    ; Retirer newline si présent
    test rbx, rbx
    jz .done
    lea rdi, [rel username]
    add rdi, rbx
    dec rdi
    cmp byte [rdi], 0x0A
    jne .done
    mov byte [rdi], 0
    
.done:
    pop rbx
    pop rbp
    ret

;  
; OBTENIR SERIAL
;  
get_serial:
    push rbp
    mov rbp, rsp
    push rbx
    
    ; Déchiffrer prompt
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
    ; Afficher prompt
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel prompt_serial]
    mov rdx, prompt_serial_len
    syscall
    
    ; Lire input
    mov rax, 0
    mov rdi, 0
    lea rsi, [rel serial]
    mov rdx, 64
    syscall
    
    ; Sauvegarder la longueur
    mov rbx, rax
    
    ; Retirer newline si présent
    test rbx, rbx
    jz .done
    lea rdi, [rel serial]
    add rdi, rbx
    dec rdi
    cmp byte [rdi], 0x0A
    jne .done
    mov byte [rdi], 0
    
.done:
    pop rbx
    pop rbp
    ret

;  
; ALGORITHME DE GÉNÉRATION DU SERIAL
;  
compute_expected_serial:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    
    ; Calculer hash du username
    xor rax, rax
    xor rbx, rbx
    lea rsi, [rel username]
    
    ; Charger les  algo constants
    mov r12d, [rel  algo1]
    mov r13d, [rel  algo2]
    mov r14d, [rel  algo3]
    
.hash_loop:
    movzx rcx, byte [rsi + rbx]
    test rcx, rcx
    jz .hash_done
    
    ; (acc * 33) ^ char ^  algo
    imul rax, 33
    xor rax, rcx
    rol rax, 7
    xor rax, r12
    
    inc rbx
    jmp .hash_loop
    
.hash_done:
    ; Mixer
    xor rax, r13
    mov rcx, rax
    rol rcx, 13
    xor rax, rcx
    xor rax, r14
    
    ; 32 bits
    and eax, 0xFFFFFFFF
    
    ; Convertir en hex
    lea rdi, [rel computed_serial]
    call hex_to_string
    
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

;  
; CONVERTIR EN HEX STRING
;  
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
    jle .is_digit
    add al, 'A' - 10
    jmp .store
.is_digit:
    add al, '0'
    
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

;  
; COMPARER SERIALS
;  
compare_serials:
    push rbp
    mov rbp, rsp
    push rbx
    
    lea rsi, [rel serial]
    lea rdi, [rel computed_serial]
    
.compare_loop:
    movzx rax, byte [rsi]
    movzx rbx, byte [rdi]
    
    ; Convertir en uppercase
    cmp al, 'a'
    jb .check1
    cmp al, 'z'
    ja .check1
    sub al, 32
    
.check1:
    cmp bl, 'a'
    jb .check2
    cmp bl, 'z'
    ja .check2
    sub bl, 32
    
.check2:
    cmp al, bl
    jne .no_match
    
    test al, al
    jz .match
    
    inc rsi
    inc rdi
    jmp .compare_loop
    
.match:
    mov rax, 1
    jmp .done
    
.no_match:
    xor rax, rax
    
.done:
    pop rbx
    pop rbp
    ret

;  
; AFFICHER MESSAGES
;  
print_success:
    push rbp
    mov rbp, rsp
    
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
    
    pop rbp
    ret

print_fail:
    push rbp
    mov rbp, rsp
    
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
    
    pop rbp
    ret

print_flag:
    push rbp
    mov rbp, rsp
    
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
    mov rdx, flag_len
    syscall
    
    pop rbp
    ret
