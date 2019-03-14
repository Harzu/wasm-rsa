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

## Usage
```javascript
import RSASetup from 'wasm-rsa'

// First peer
let signature = null
let privateKeys = null
let privateN = null
let privateE = null
RSASetup().then(instance => {
  privateKeys = instance.generateRSAPrivate(1024)
  signature = instance.signMessage('Hello')
  privateN = instance.getN()
  privateE = instance.getE()
})

// Second peer
RSASetup().then(instance => {
  const publicKeys = instance.createRSAPublic(privateN, privateE)
  const verify = instance.verify('Hello', signature)
  
  if (verify) {
    console.log('verify success')
  }
})
```

## TypeScript

for typescript can import interface
```javascript
import RSASetup, { RSAInterface } from 'wasm-rsa'
```
