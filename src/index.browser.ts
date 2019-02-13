import RSA from './Rsa'
import { RSAInterface } from './interfaces'

export default async function RSASetup(): Promise<RSAInterface> {
  const wasm = await import('../wasm/browser/rsa_lib').then((instance) => instance)
  return new RSA(wasm)
}

export { RSAInterface }
