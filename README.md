# WASM RSA
WebAssembly rsa library for generate keys and sign/verify message

## Install
```shell
npm i wasm-rsa
```

## Usage
```javascript
import RSA from 'wasm-rsa'

// First peer
const rsa = new RSA()
const privateKeys = rsa.generateRSAPrivate(1024)
const signature = rsa.signMessage('Hello')

// Second peer
const rsa = new RSA()
const publicKeys = rsa.createRSAPublic(privateN, privateE)
const verify = rsa.verify('Hello', signature)

if (verify) {
  console.log('verify success')
}
```

## TypeScript

for typescript can import interface
```javascript
import RSA, { RSAInterface } from 'wasm-rsa'
```