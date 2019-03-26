import {
  RSAPublic,
  RSAPrivate,
  RSAInterface,
  RSAPublicKeyInterface,
  RSAPrivateKeyInterface,
} from './interfaces'
import { randomBytes } from 'crypto'

export default class RSA implements RSAInterface {
  public static IS_BROWSER: boolean = (typeof window !== 'undefined')

  private publicInstance: RSAPublicKeyInterface
  private privateInstance: RSAPrivateKeyInterface

  constructor(wasm) {
    this.publicInstance = new wasm.RSAPublicKeyPair()
    this.privateInstance = new wasm.RSAPrivateKeyPair()
  }

  generateRSAPrivate(bits: number): RSAPrivate {
    if (typeof bits !== 'number') {
      throw new Error(`Invalid bits ${bits}`)
    }

    try {
      const randomSeed = randomBytes(32).toString('hex')
      this.privateInstance.generate(bits, randomSeed)

      return {
        d: this.privateInstance.get_d(),
        n: this.privateInstance.get_n(),
        e: this.privateInstance.get_e(),
        primes: this.privateInstance.get_primes().split('_'),
      }
    } catch (error) {
      throw error
    }
  }

  generateRSAPrivateFrom(n: string, d: string, e: string, primes: string[]): RSAPrivate {
    if (!n || !d || !e || !primes) {
      throw new Error('not all data for create keys')
    }

    if (primes.length === 0) {
      throw new Error('primes empty')
    }

    try {
      this.privateInstance.generate_from(n, d, e, primes.join('_'))
      return {
        primes,
        d: this.privateInstance.get_d(),
        n: this.privateInstance.get_n(),
        e: this.privateInstance.get_e(),
      }
    } catch (error) {
      throw error
    }
  }

  createRSAPublic(n: string, e: string): RSAPublic {
    if (!n || !e || n.length < 1 || e.length < 1) {
      throw new Error(`Invalid params for create n: ${n} e: ${e}`)
    }

    try {
      this.publicInstance.create(n, e)

      return {
        n: this.publicInstance.get_n(),
        e: this.publicInstance.get_e(),
      }
    } catch (error) {
      throw error
    }
  }

  getRSAPrivate(): RSAPrivate {
    const d = this.privateInstance.get_d()
    const n = this.privateInstance.get_n()
    const e = this.privateInstance.get_e()
    const primes = this.privateInstance.get_primes().split('_')

    if (d.length < 1 || n.length < 1 || e.length < 1) {
      throw new Error(`All rsa private keys not created d: ${d} n: ${n} e: ${e}`)
    }

    return { d, n, e, primes }
  }

  getPrivatePrimes(): string[] {
    const primes = this.privateInstance.get_primes()
    return primes.split('_')
  }

  getRSAPublic(): RSAPublic {
    const n = this.publicInstance.get_n()
    const e = this.publicInstance.get_e()

    if (n.length < 1 || e.length < 1) {
      throw new Error(`All rsa public keys not created n: ${n} e: ${e}`)
    }

    return { n, e }
  }

  signMessage(message: string): string {
    if (typeof message !== 'string') {
      throw new Error('message should be a string')
    }

    try {
      const signature = this.privateInstance.sign_message(message)
      return signature
    } catch (error) {
      throw error
    }
  }

  verify(message: string, signature: string): boolean {
    try {
      const verify = this.publicInstance.verify_message(message, signature)
      if (!verify) {
        throw new Error('Verify message is false')
      }

      return verify
    } catch (error) {
      throw error
    }
  }

  publicEncrypt(message: string): string {
    try {
      if (!message) {
        throw new Error('message is not define')
      }
      const randomSeed = randomBytes(32).toString('hex')
      return this.publicInstance.encrypt(message, randomSeed)
    } catch (error) {
      throw error
    }
  }

  privateDecrypt(encryptedMessage: string): string {
    try {
      if (!encryptedMessage) {
        throw new Error('message is not define')
      }

      return this.privateInstance.decrypt(encryptedMessage)
    } catch (error) {
      throw error
    }
  }
}
