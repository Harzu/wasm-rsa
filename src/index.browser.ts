import RSA from './Rsa'
import { RSAInterface } from './interfaces'

/**
 * @desc function for init rsa instance in browser
 * @example
 * // Promise syntax
 * RSASetup().then(rsaInstance => {
 *    // code...
 * })
 *
 * // Async/Await syntax
 * const rsaInstance = await RSASetup()
 */
export default async function RSASetup(): Promise<RSAInterface> {
  const wasm = await import('../wasm/browser/rsa_lib').then((instance) => instance)
  return new RSA(wasm)
}

export { RSAInterface }
