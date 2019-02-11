import {
  RSAPublic,
  RSAPrivate,
  RSAInterface,
  RSAPublicKeyInterface,
  RSAPrivateKeyInterface,
} from './interfaces'

export default class RSA implements RSAInterface {
  public static IS_BROWSER: boolean = (typeof window !== 'undefined')

  private publicInstance: RSAPublicKeyInterface
  private privateInstance: RSAPrivateKeyInterface

  constructor() {
    const wasm = (RSA.IS_BROWSER)
      ? require('../wasm/browser/rsa_lib')
      : require('../wasm/nodejs/rsa_lib')

    this.publicInstance = new wasm.RSAPublicKeyPair()
    this.privateInstance = new wasm.RSAPrivateKeyPair()
  }

  generateRSAPrivate(bits: number): RSAPrivate {
    if (typeof bits !== 'number') {
      throw new Error(`Invalid bits ${bits}`)
    }

    try {
      this.privateInstance.generate(bits)

      return {
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
    const e = this.privateInstance.get_d()

    if (d.length < 1 || n.length < 1 || e.length < 1) {
      throw new Error(`All rsa private keys not created d: ${d} n: ${n} e: ${e}`)
    }

    return { d, n, e }
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
}

export { RSAInterface }
