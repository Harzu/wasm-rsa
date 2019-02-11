
const path = require('path').join(__dirname, 'rsa_lib_bg.wasm');
const bytes = require('fs').readFileSync(path);
let imports = {};
imports['./rsa_lib'] = require('./rsa_lib');

const wasmModule = new WebAssembly.Module(bytes);
const wasmInstance = new WebAssembly.Instance(wasmModule, imports);
module.exports = wasmInstance.exports;
