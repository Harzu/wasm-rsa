import RSA from './Rsa'
import wasm from '../wasm/nodejs/rsa_lib'
import { RSAInterface } from './interfaces'

export default function RSAInit(): RSAInterface {
  return new RSA(wasm)
}
