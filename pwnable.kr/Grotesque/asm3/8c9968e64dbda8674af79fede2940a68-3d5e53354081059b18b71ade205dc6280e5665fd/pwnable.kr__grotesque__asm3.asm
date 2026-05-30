BITS 64
; nasm -f bin shellcode.asm

; rdi -> ptr_array
; esi -> val

_start:
  ; save values
  mov r8, rdi
  mov r9d, esi
  xor r12, r12     ; idx
  _loop:
    ; mprotect(addr, 1024, PROT_READ)
    mov r10, [r8 + r12*8]
    mov rdi, r10
    mov rsi, 4096
    mov rdx, 1
    mov rax, 10
    syscall

    ; read byte and compare
    mov al, byte [r10]       ; found
    cmp al, r9b              ; found == expected ?
    je _end


    inc r12
    jmp _loop
  _end:
    ; exit(idx)
    mov rdi, r12
    mov rax, 60
    syscall