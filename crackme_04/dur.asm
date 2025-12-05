section .data
    p db "Password: ", 0
    ok db "bien joue visite mon site maintenant :)", 10, 0
    no db "Paaaaaas du tout !", 10, 0
    
    vm_code db 0x01, 0x00, 0x01, 0x02, 0x00, 0x00, 0x01, 0x01, 0x05, 0x02, 0x01, 0x01
            db 0x04, 0x00, 0x01, 0x01, 0x01, 0x08, 0x02, 0x01, 0x01, 0x05, 0x00, 0x01
            db 0x01, 0x01, 0x0b, 0x02, 0x01, 0x01, 0x04, 0x00, 0x01, 0x03, 0x00, 0x12
            db 0x00, 0x00, 0x00

    enc db 0xcf, 0xdc, 0x93, 0xfa, 0x7c, 0xd2, 0xa6, 0x9f, 0x29, 0x1f, 0x6e, 0xd0, 0x65, 0x64, 0x00

section .bss
    buf resb 64
    regs resb 32
    t1 resq 1

section .text
global _start

_start:
    mov rax, 1
    mov rdi, 1
    lea rsi, [p]
    mov rdx, 8
    syscall

    xor rax, rax
    xor rdi, rdi
    lea rsi, [buf]
    mov rdx, 63
    syscall
    dec rax
    cmp rax, 14
    jne .bad

    lea rsi, [buf]
    xor rcx, rcx
    xor rax, rax
.sum:
    cmp rcx, 14
    je .ck1
    movzx ebx, byte [rsi + rcx]
    add rax, rbx
    imul rax, 0x1f
    ror rax, 3
    inc rcx
    jmp .sum

.ck1:
    mov rbx, 0x364d0788ae71e715
    cmp rax, rbx
    jne .bad

    lea rsi, [buf]
    movzx eax, byte [rsi]
    movzx ebx, byte [rsi + 6]
    xor eax, ebx
    movzx ecx, byte [rsi + 13]
    xor eax, ecx
    cmp al, 0x2a
    jne .bad

    movzx eax, byte [rsi + 2]
    movzx ebx, byte [rsi + 4]
    add eax, ebx
    movzx ecx, byte [rsi + 9]
    sub eax, ecx
    cmp al, 0x44
    jne .bad

    lea rdi, [regs]
    xor rax, rax
    mov rcx, 4
    rep stosq

    lea rsi, [vm_code]
    lea rdi, [regs]
    lea r8, [buf]

.vm:
    movzx eax, byte [rsi]
    test al, al
    jz .ck2
    cmp al, 0x01
    je .vm_mov
    cmp al, 0x02
    je .vm_ld
    cmp al, 0x03
    je .vm_cmp
    cmp al, 0x04
    je .vm_xor
    cmp al, 0x05
    je .vm_add
    cmp al, 0x06
    je .vm_sub
    cmp al, 0x07
    je .vm_mul
    jmp .bad

.vm_mov:
    movzx ebx, byte [rsi + 1]
    movzx ecx, byte [rsi + 2]
    mov byte [rdi + rbx], cl
    add rsi, 3
    jmp .vm

.vm_ld:
    movzx ebx, byte [rsi + 1]
    movzx ecx, byte [rsi + 2]
    movzx eax, byte [rdi + rcx]
    movzx eax, byte [r8 + rax]
    mov byte [rdi + rbx], al
    add rsi, 3
    jmp .vm

.vm_cmp:
    movzx ebx, byte [rsi + 1]
    movzx ecx, byte [rsi + 2]
    movzx eax, byte [rdi + rbx]
    cmp al, cl
    jne .bad
    add rsi, 3
    jmp .vm

.vm_xor:
    movzx ebx, byte [rsi + 1]
    movzx ecx, byte [rsi + 2]
    movzx eax, byte [rdi + rbx]
    movzx edx, byte [rdi + rcx]
    xor eax, edx
    mov byte [rdi + rbx], al
    add rsi, 3
    jmp .vm

.vm_add:
    movzx ebx, byte [rsi + 1]
    movzx ecx, byte [rsi + 2]
    movzx eax, byte [rdi + rbx]
    movzx edx, byte [rdi + rcx]
    add eax, edx
    mov byte [rdi + rbx], al
    add rsi, 3
    jmp .vm

.vm_sub:
    movzx ebx, byte [rsi + 1]
    movzx ecx, byte [rsi + 2]
    movzx eax, byte [rdi + rbx]
    movzx edx, byte [rdi + rcx]
    sub eax, edx
    mov byte [rdi + rbx], al
    add rsi, 3
    jmp .vm

.vm_mul:
    movzx ebx, byte [rsi + 1]
    movzx ecx, byte [rsi + 2]
    movzx eax, byte [rdi + rbx]
    movzx edx, byte [rdi + rcx]
    imul eax, edx
    mov byte [rdi + rbx], al
    add rsi, 3
    jmp .vm

.ck2:
    lea rsi, [buf]
    lea rdi, [enc]
    xor rcx, rcx
    mov bl, 0x37
.dec:
    cmp rcx, 14
    je .ck3
    movzx eax, byte [rsi + rcx]
    xor al, bl
    add al, cl
    rol al, 4
    xor al, 0x5a
    movzx edx, byte [rdi + rcx]
    cmp al, dl
    jne .bad
    add bl, al
    xor bl, cl
    inc rcx
    jmp .dec

.ck3:
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