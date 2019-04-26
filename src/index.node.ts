import RSA from './Rsa'
import * as wasm from '../wasm/nodejs/rsa_lib'
import { RSAInterface } from './interfaces'

/**
 * @desc function for init rsa instance in node
 * @example
 * // Promise syntax
 * RSASetup().then(rsaInstance => {
 *    // code...
 * })
 * // Async/Await syntax
 * const rsaInstance = await RSASetup()
 */
export default function RSASetup(): Promise<RSAInterface> {
  return new Promise((resolve) => resolve(new RSA(wasm)))
}

export { RSAInterface }
