import RSA from './Rsa'
import { RSAInterface } from './interfaces'

export default async function RSAInit(): Promise<RSAInterface> {
  const wasm = await import('../wasm/browser/rsa_lib')
  return new RSA(wasm)
}
