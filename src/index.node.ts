import RSA from './Rsa'
import * as wasm from '../wasm/nodejs/rsa_lib'
import { RSAInterface } from './interfaces'

export default function RSASetup(): Promise<RSAInterface> {
  return new Promise((resolve) => resolve(new RSA(wasm)))
}

export { RSAInterface }
