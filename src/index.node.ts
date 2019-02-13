import RSA from './Rsa'
import * as wasm from '../wasm/nodejs/rsa_lib'
import { RSAInterface } from './interfaces'

export default function RSASetup(): RSAInterface {
  return new RSA(wasm)
}

export { RSAInterface }
