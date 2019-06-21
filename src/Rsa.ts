import {
  RSAPublic,
  RSAPrivate,
  RSAInterface,
  RSAPublicKeyInterface,
  RSAPrivateKeyInterface,
} from './interfaces'
import randomBytes from 'randombytes'

/**
 * @desc facade on wasm code.
 * @access private
 * @example
 * import RSASetup from 'wasm-rsa'
 * const rsaInstance = await RSASetup()
 */
export default class RSA implements RSAInterface {
  public static IS_BROWSER: boolean = (typeof window !== 'undefined')

  private publicInstance: RSAPublicKeyInterface
  private privateInstance: RSAPrivateKeyInterface
  /** @ignore */
  constructor(wasm) {
    /** @ignore */
    this.publicInstance = new wasm.RSAPublicKeyPair()
    /** @ignore */
    this.privateInstance = new wasm.RSAPrivateKeyPair()
  }

  /**
   * @typedef {Object} RSAPrivate
   * @property {string} n - public piece rsa key
   * @property {string} e - public piece rsa key
   * @property {string} d - private piece rsa key
   * @property {Array} primes - array of big numbers which create key pair
   */

   /**
    * @typedef {Object} RSAPublic
    * @property {string} n - public piece rsa key
    * @property {string} e - public piece rsa key
    */

  /**
   * @desc Generate private key pair
   * @param {number} bits - count bits for create rsa keys.
   * @returns {RSAPrivate} - generated keys
   * @example
   * const { n, e, d, primes } = rsaInstance.generateRSAPrivate(2048)
   */
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
  /**
   * @desc Generate private key pair from n, d, e, primes
   * @param {string} n - public piece rsa key
   * @param {string} e - public piece rsa key
   * @param {string} d - private piece rsa key
   * @param {Array} primes - array of big numbers which create key pair
   * @returns {RSAPrivate} - generated keys
   * @example
   * const privateKeys = rsaInstance.generateRSAPrivateFrom(n, d, e, primes)
   */
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
  /**
   * @desc Generate public keys from n, e
   * @param {string} n - public piece rsa key
   * @param {string} e - public piece rsa key
   * @returns {RSAPublic} - generated keys
   * @example
   * const publicKeys = rsaInstance.createRSAPublic(n, e)
   */
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

  /**
   * @desc Get private key pair
   * @returns {RSAPrivate} - private keys
   * @example
   * const { n, d, e, primes } = rsaInstance.getRSAPrivate()
   */
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

  /**
   * @desc Get private primes
   * @returns {Array} - private primes
   * @example
   * const primes = rsaInstance.getPrivatePrimes()
   */
  getPrivatePrimes(): string[] {
    const primes = this.privateInstance.get_primes()
    return primes.split('_')
  }

  /**
   * @desc Get public keys
   * @returns {RSAPublic} - private keys
   * @example
   * const { n, e } = rsaInstance.getRSAPublic()
   */
  getRSAPublic(): RSAPublic {
    const n = this.publicInstance.get_n()
    const e = this.publicInstance.get_e()

    if (n.length < 1 || e.length < 1) {
      throw new Error(`All rsa public keys not created n: ${n} e: ${e}`)
    }

    return { n, e }
  }

  /**
   * @desc sign message with private keys
   * @param {string} message - message for sign
   * @returns {string} - signature string
   * @example
   * const signature = rsaInstance.signMessage('hello')
   *
   * signature -> `5d21446e76ff38fe4688c1e7fd75c785d98cd7c5fabfd483c3cd27898d8e2931b176609bb5d28e5d6319c3e814ebcd96ae58
   * 2ab3984b5309678d421672635b3fd643e840a1efa2e9cba7d27afaeb8534ca6338bf73aa10864f3406f1c484a85012d1c1a9
   * 87398f28b75d8b79c521d548a944a4eaa1bfe56c0b715b43dede3d41`
   */
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

  /**
   * @desc verify signature with public keys
   * @param {string} message - signature data
   * @param {string} signature - signature
   * @returns {boolean} - verify result
   * @example
   * const verify = rsaInstance.verify(
   *  'hello',
   *  `5d21446e76ff38fe4688c1e7fd75c785d98cd7c5fabfd483c3cd27898d8e2931b176609bb5d28e5d6319c3e814ebcd96ae58
   *   2ab3984b5309678d421672635b3fd643e840a1efa2e9cba7d27afaeb8534ca6338bf73aa10864f3406f1c484a85012d1c1a9
   *   87398f28b75d8b79c521d548a944a4eaa1bfe56c0b715b43dede3d41`
   * )
   *
   * verify -> true
   */
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

  /**
   * @desc encryption message with public keys
   * @param {string} message - data for encrypt
   * @returns {string} - encrypted data
   * @example
   * const encryptedMessage = rsaInstance.publicEncrypt('hello')
   *
   * encryptedMessage -> `ca6e7d0571563b46b82a873c196e53d7322f2d5f510a5185d4a94b0ecbfea966160
   * d4b0be160684a5b9b0c2b6d429d331a950210e5545ee133793f604f417f93c63af4509db79f90a89d0c87c7c
   * 87dc6873a89575b0c985f8cc159bae781f88607c4ed8d2a6df4aac33c0ca91581debe50b7fef2fc76e71ad7c
   * e3c0191d7c1497199c2a317bd475a27988d71bfa5a33d23d1be19791a9bded0292836b0d10e5e4d7fa1bd092
   * 9f5cabdb6082f2882c12dadebe23b3682e625618cd5a57d9727eb06192ab4703277128771d193aa69ea30123
   * 409c7205827375c34d4c22544d09c1c128d8edd9124d62aa062f6642bd7e3e468888e1a78c7e80206361ef131ecee`
   */
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
  /**
   * @desc decrypt message with private keys
   * @param {string} encryptedMessage - data for dencrypt
   * @returns {string} - message
   * @example
   * const decryptMessage = rsaInstance.privateDecrypt(
   *  `ca6e7d0571563b46b82a873c196e53d7322f2d5f510a5185d4a94b0ecbfea966160
   *   d4b0be160684a5b9b0c2b6d429d331a950210e5545ee133793f604f417f93c63af4509db79f90a89d0c87c7c
   *   87dc6873a89575b0c985f8cc159bae781f88607c4ed8d2a6df4aac33c0ca91581debe50b7fef2fc76e71ad7c
   *   e3c0191d7c1497199c2a317bd475a27988d71bfa5a33d23d1be19791a9bded0292836b0d10e5e4d7fa1bd092
   *   9f5cabdb6082f2882c12dadebe23b3682e625618cd5a57d9727eb06192ab4703277128771d193aa69ea30123
   *   409c7205827375c34d4c22544d09c1c128d8edd9124d62aa062f6642bd7e3e468888e1a78c7e80206361ef131ecee`
   * )
   *
   * decryptMessage -> 'hello'
   */
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
