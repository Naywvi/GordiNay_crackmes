section .data
    p db "Password: ", 0
    ok db "bien joue visite mon site maintenant :)", 10, 0
    no db "Paaaaaas du tout !", 10, 0
    k db 0x7d, 0xe8, 0x02, 0x40, 0x33, 0x10, 0x45, 0x39, 0x4d, 0xa5, 0xe7, 0x31, 0x00

section .bss
    buf resb 64

section .text
global _start

_start:
    mov rax, 1
    mov rdi, 1
    lea rsi, [p]
    mov rdx, 10
    syscall

    xor rax, rax
    xor rdi, rdi
    lea rsi, [buf]
    mov rdx, 63
    syscall
    dec rax
    mov r8, rax

    cmp r8, 12
    jne .bad

    xor rcx, rcx
    mov bl, 0x13
.loop:
    cmp rcx, 12
    je .good
    movzx eax, byte [buf + rcx]
    xor al, bl
    add bl, al
    rol bl, 3
    movzx edx, byte [k + rcx]
    cmp al, dl
    jne .bad
    inc rcx
    jmp .loop

.good:
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