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

    const randomSeed = randomBytes(32).toString('hex')
    this.privateInstance.generate(bits, randomSeed)

    return {
      d: this.privateInstance.get_d(),
      n: this.privateInstance.get_n(),
      e: this.privateInstance.get_e(),
      primes: this.privateInstance.get_primes().split('_'),
    }
  }
  /**
   * @desc Generate private key pair from n, d, e, primes
   * @param {string} n - public piece rsa key
   * @param {string} d - private piece rsa key
   * @param {string} e - public piece rsa key
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

    this.privateInstance.generate_from(n, d, e, primes.join('_'))

    return {
      primes,
      d: this.privateInstance.get_d(),
      n: this.privateInstance.get_n(),
      e: this.privateInstance.get_e(),
    }
  }

  /**
   * @desc Generate private key from pem key format
   * @param {string} key - private key in PEM format
   * @returns {RSAPublic} - generated keys
   * @example
   * const publicKey = rsaInstance.createRSAPrivateFromPEM(`-----BEGIN PRIVATE KEY-----
   * MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDD/UjzFPIp85KE
   * Ga4rhPYY0/8MszqrNHcyoogVXyg5MTXCee6nQPOk88HLsDM2KW7JBtvc2LDbzPVm
   * P6ZxqRsj03T3VrC4YOari460Jn9J6L4ueKvUagkxxF2XyaB7yuoblFmuTsZA98Zj
   * wAgfPA4G2PaeaxtdzWWXV4ehmGoXslKFzNnMSBLu/a+GROrWTT/5vg1jybXrppeD
   * cTeBBE+vbcv9k/Al7j6eIwCi0ObZYoEEET+3Et5hGv6w7qrH+Ds0MBhesSMmVLSm
   * vkEMaJxUcWGnIQazgghFjnFvnQkF57zJsMl/sTjm7QkA9IIxejPGvfgARbP1aAAv
   * UMtjpoULAgMBAAECggEABYwix3adUCCr0f9kFalCyfseKf7ct0HZ6d392hUCb3P8
   * IJAQ+Dz3aIDZyGkpWewcTaZbDMo5X09S1t0QWgE+Wmo+0k1q3R0pCkv98w1v5uim
   * kWwq+O0za2wydfxoBXj93V/6ldt28xnQTLx/vlqVzw3PFTbU5HfO21TH6wQEZL1D
   * rhEshddoU9a9qrqzsVFNLUiGHAvMR7YijagLl0t2LMSfeIt5qS4Rj7fCyXGzNNSx
   * 01h31IfVSUT1FdWTf+fRAYF20nupqejzLjRc5srNoTrQnK7otDFYFxiwb/E2/Dte
   * I6kIr5SgscOBoQizBPL/yINgWjWHYUrMRyX+EN2sqQKBgQDOtX4Zs4QDNFT7otjL
   * D1JNIY6bcic0P86XMq6LNSV5o6JmxNDMlPD/EjVAicjOxn1LYbnzIQyuzOVrNXm0
   * +QA8dsJMyQzzNO7o6t9lLtrG+CXBKP7wmVBb8mMWve0VKNeLZyOpbOamGC1P7mPp
   * JVoRh+8DAVzKPXlEaKXXLasZHwKBgQDyuWs8b/6wv1d8WGZoXYuCkL1l/ywNidZP
   * AeBys4FXdqN6luOuCIoMpu7sOzCT7exu5pz3toB74bwVGRsSlcp3LJirb8LN4U3o
   * jkD3Tp8Gn7f7pUE43ZphU8B25ebAMBgCC5V+77HVIlo8GmLFz0M5XAslWtZ6GMmr
   * XF3HhERalQKBgEejfN15aqIVq/I94PaXC8XxgFP9PvsLthSOmxFhzOgYPvtw8JBG
   * ejNcYxpH5lFLVzcd2m0ZoiSenFAIi3Kd7WgHHJWyBAvx527Pn7aYg3f7nlIQXDKU
   * X9ZN7et+zUDNE86bYy+fr1wW+vU9wGCX8lwrCTm4aikpHvMHdZpamHavAoGADYSq
   * JkmOg8WEV9aMjY94L6NkCQQ3LeHZX7kZCQpaT8a5wCAbOhwbpCy/7cQ2Jmb/3gVW
   * BK3TZhLiaMJnMZfKGO0Q66tjzBeaQTN7BssILFRE6O0BPuuIp5cEhxqyyU1kaOjA
   * QLuUyewJ3oMRsTaj5dPsgv4WJ+KtiK+yQWRqcikCgYAwRzXzsrGK2HpkER3sEXok
   * hydDHbuqKLuT2Cqe6wyBpJPq5MyMu/T7ANmAPtJK4nvQF5RQoGdTne6/lvvwNMf2
   * ullviEZz1ehunkmoU25CgAKLXXCMmw/T8GyX6UUIqofyFGHasj/vjA8ZIpdLyKVP
   * khSri8NDQTao0i43teKIMA==
   * -----END PRIVATE KEY-----`)
   */
  createRSAPrivateFromPEM(key: string): RSAPrivate {
    if (!key) {
      throw new Error('empty key')
    }

    this.privateInstance.from_pkcs8_pem(key)

    return {
      d: this.privateInstance.get_d(),
      n: this.privateInstance.get_n(),
      e: this.privateInstance.get_e(),
      primes: this.privateInstance.get_primes().split('_'),
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

    this.publicInstance.create(n, e)

    return {
      n: this.publicInstance.get_n(),
      e: this.publicInstance.get_e(),
    }
  }

  /**
   * @desc Create public key from pem key format
   * @param {string} key - public key in PEM format
   * @returns {RSAPublic} - generated keys
   * @example
   * const publicKey = rsaInstance.createRSAPublicFromPEM(`-----BEGIN PUBLIC KEY-----
   * MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw/1I8xTyKfOShBmuK4T2
   * GNP/DLM6qzR3MqKIFV8oOTE1wnnup0DzpPPBy7AzNiluyQbb3Niw28z1Zj+mcakb
   * I9N091awuGDmq4uOtCZ/Sei+Lnir1GoJMcRdl8mge8rqG5RZrk7GQPfGY8AIHzwO
   * Btj2nmsbXc1ll1eHoZhqF7JShczZzEgS7v2vhkTq1k0/+b4NY8m166aXg3E3gQRP
   * r23L/ZPwJe4+niMAotDm2WKBBBE/txLeYRr+sO6qx/g7NDAYXrEjJlS0pr5BDGic
   * VHFhpyEGs4IIRY5xb50JBee8ybDJf7E45u0JAPSCMXozxr34AEWz9WgAL1DLY6aF
   * CwIDAQAB
   * -----END PUBLIC KEY-----`)
   */
  createRSAPublicFromPEM(key: string): RSAPublic {
    if (!key) {
      throw new Error('empty key')
    }

    this.publicInstance.from_pkcs8_pem(key)

    return {
      n: this.publicInstance.get_n(),
      e: this.publicInstance.get_e(),
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

    return this.privateInstance.sign_message(message)
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
    const verify = this.publicInstance.verify_message(message, signature)

    if (!verify) {
      throw new Error('Verify message is false')
    }

    return verify
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
    if (!message) {
      throw new Error('message is not define')
    }

    const randomSeed = randomBytes(32).toString('hex')
    return this.publicInstance.encrypt(message, randomSeed)
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
    if (!encryptedMessage) {
      throw new Error('message is not define')
    }

    return this.privateInstance.decrypt(encryptedMessage)
  }

  /**
   * @desc generate private key in PEM format
   * @returns {string} - key
   * @example
   * const privatePEM = rsaInstance.privateKeyToPEM()
   * console.log(privatePEM)
   * -----BEGIN RSA PRIVATE KEY-----
   * MIICXAIBAAKBgQCtelj+ptZ69rtp4unsbbRFygYpaZc0/GgRkJSwav891WjZk/dp
   * /J71s4cjJuKgbnN7wKt2ECoeBEzr/BAWc/y9dh1dLdSoHnl2LPVLindFRC3o7UZu
   * mogz4X1bxlb6lEh2TV04nrt9615e1+RS9zIBP0HGr2ZG4qhd58SH1NGSZQIDAQAB
   * AoGAAR1JFxGxTQbqu0pm4ErwHoamtXtlKkT40iwQmHWHgDkvvD4UF800pDVsB9DH
   * IeqzuTbKoy6FZr32VInA/LPwCrDSmeD2HNuGiwIjTvBl1QOnwG8KzfFSXHV3ZVn7
   * 4Gb4QEOdB8osPhi7uU+a6lksSudNLKoLUIX0YqD1aWQtMAECQQDdQXmfeJyeHRdI
   * nOAyseTLCzBoHJONoAVtbeyLt2colG7BzyDDxKanj9LsMtkdtLOVymHmvVUJHv2I
   * Lex1jSZlAkEAyLgxp+dninReelj7Bwk7FY2wIeb5/E3dE3brC6mtqVRrWh8tn1pm
   * yRWqH9mjJRv29DZZtJs41LpGoAUQX4X8AQJACobI8IteeC9OIkhEamUIS5i2rt1d
   * L8nDOFeYf3U0VTvqoRHnryi1/RbcpBwvNDiaqq+8RKwRVaPB0C7PJzCV+QJAMBZY
   * 5yX8W2JXxC4PLfdbLWW9ndGtcHHjFie2Vhv3nAq6kWPI1VWeLGzBTlIg0OIrPwTK
   * ZweNDQH3q5yq+IesAQJBANcdJLlwriLwzXnDeDbki/M/TUssiVGtCWLnrxwT1Yi8
   * IAxrYAWdS9Qb/EaZamqyMKizp9kyMSpPwWHhFSJtT58=
   * -----END RSA PRIVATE KEY-----
   */
  privateKeyToPEM(): string {
      return this.privateInstance.to_pkcs8_pem()
  }

  /**
   * @desc generate public key in PEM format
   * @returns {string} - key
   * @example
   * const publicPEM = rsaInstance.publicKeyToPEM()
   * console.log(publicPEM)
   * -----BEGIN RSA PUBLIC KEY-----
   * MIGJAoGBAK16WP6m1nr2u2ni6exttEXKBilplzT8aBGQlLBq/z3VaNmT92n8nvWz
   * hyMm4qBuc3vAq3YQKh4ETOv8EBZz/L12HV0t1KgeeXYs9UuKd0VELejtRm6aiDPh
   * fVvGVvqUSHZNXTieu33rXl7X5FL3MgE/QcavZkbiqF3nxIfU0ZJlAgMBAAE=
   * -----END RSA PUBLIC KEY-----
   */
  publicKeyToPEM(): string {
    return this.publicInstance.to_pkcs8_pem()
  }
}
