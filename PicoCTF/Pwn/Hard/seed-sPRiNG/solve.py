import sys
import socket
from ctypes import CDLL

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect((sys.argv[1],int(sys.argv[2])))

libc = CDLL("libc.so.6")
libc.srand(libc.time(0))

for _ in range(30):
    height = str(libc.rand() & 0xf).encode()
    s.send(height + b"\n")

output = s.recv(1024*0x20)

print(output.decode())
