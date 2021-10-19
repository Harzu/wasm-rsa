# WASM RSA
[![npm downloads](https://img.shields.io/npm/dt/wasm-rsa.svg)](https://www.npmjs.com/package/wasm-rsa)
[![npm](https://img.shields.io/npm/v/wasm-rsa.svg?maxAge=2592000)](https://www.npmjs.com/package/wasm-rsa)

WebAssembly rsa library for generate keys and sign/verify message in nodejs and browsers

## Install
```shell
npm i wasm-rsa
```

## Examples

webpack 4 example - [webpack_four](https://github.com/Harzu/wasm-rsa/tree/master/examples/webpack_four)

## Docs - [Click here](https://harzu.github.io/wasm-rsa/)

## Usage
```javascript
import RSASetup from 'wasm-rsa'

// Promise syntax
RSASetup().then(rsaInstance => {
  // code...
})

// Async/Await syntax
const rsaInstance = await RSASetup()
// code...
```

## TypeScript

for typescript can import interface
```javascript
import RSASetup, { RSAInterface } from 'wasm-rsa'
```

## For developers

install rust
```shell
curl https://sh.rustup.rs -sSf | sh
rustup target add wasm32-unknown-unknown
cargo check --target wasm32-unknown-unknown
```

install wasm-pack cli
```shell
curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh;
```

clone repo
```shell
git clone https://github.com/Harzu/wasm-rsa.git
```

build
```shell
npm run build
```

Run test
```shell
npm run test
```
