section .data
    p db "password: ", 0
    ok db "bien joue visite mon site maintenant :)", 10, 0
    no db "Paaaaaas du tout !", 10, 0

section .bss
    buf resb 32

section .text
global _start

_start:
    mov rax, 1
    mov rdi, 1
    lea rsi, [p]
    mov rdx, 5
    syscall

    xor rax, rax
    xor rdi, rdi
    lea rsi, [buf]
    mov rdx, 31
    syscall
    dec rax
    cmp rax, 11
    jne .bad

    lea rsi, [buf]
    mov rax, 0x5381
    xor rcx, rcx
.hash:
    cmp rcx, 11
    je .check
    movzx ebx, byte [rsi + rcx]
    imul rax, 33
    add rax, rbx
    inc rcx
    jmp .hash

.check:
    mov rbx, 0x94802ffdffce0dad
    cmp rax, rbx
    jne .bad

    movzx eax, byte [rsi]
    movzx ebx, byte [rsi + 10]
    xor eax, ebx
    cmp al, 0x1c
    jne .bad

    movzx eax, byte [rsi + 3]
    movzx ebx, byte [rsi + 7]
    add eax, ebx
    cmp al, 0xd8
    jne .bad

    mov rax, 1
    mov rdi, 1
    lea rsi, [ok]
    mov rdx, 41
    syscall
    jmp .exit

.bad:
    mov rax, 1
    mov rdi, 1
    lea rsi, [no]
    mov rdx, 3
    syscall

.exit:
    mov rax, 60
    xor rdi, rdi
    syscall