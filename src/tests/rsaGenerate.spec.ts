import 'mocha'
import RSASetup from '../index.node'
import { expect } from 'chai'

let rsaOne = null
let rsaTwo = null
const bits = 2048

describe('RSA generate keys', () => {
  beforeEach(async () => {
    rsaOne = await RSASetup()
    rsaTwo = await RSASetup()
  })

  it('OK: generate private key pair', () => {
    // Act
    const key = rsaOne.generateRSAPrivate(bits)
    // Assert
    expect(key).to.have.property('n')
    expect(key).to.have.property('d')
    expect(key).to.have.property('e')
    expect(key.e.length).to.be.least(1)
    expect(key.n.length).to.be.least(1)
    expect(key.d.length).to.be.least(1)
    expect(Number(key.e)).not.to.be.eq(NaN)
  })

  it('OK: generate another key', () => {
    // Act
    const keyFirst = rsaOne.generateRSAPrivate(bits)
    const keySecond = rsaOne.generateRSAPrivate(bits)
    // Assert
    expect(keyFirst.d).not.to.be.equal(keySecond.d)
    expect(keyFirst.n).not.to.be.equal(keySecond.n)
  })

  it('FAIL: generate private key pair with invalid bits', () => {
    // Arrange
    let errorMessage = null
    // Act
    try {
      rsaOne.generateRSAPrivate('dsadas')
    } catch (error) {
      errorMessage = error.message
    }
    // Assert
    expect(errorMessage).not.to.be.eq(null)
  })

  it('OK: create public key', () => {
    // Act
    const { n, e } = rsaOne.generateRSAPrivate(bits)
    const publicKey = rsaTwo.createRSAPublic(n, e)
    // Assert
    expect(publicKey).to.have.property('n')
    expect(publicKey).to.have.property('e')
    expect(publicKey.e.length).to.be.least(1)
    expect(publicKey.n.length).to.be.least(1)
    expect(Number(publicKey.e)).not.to.be.eq(NaN)
  })

  it('FAIL: create public key with invalid e', () => {
    // Arrange
    let errorMessage = null
    // Act
    try {
      const privateKey = rsaOne.generateRSAPrivate(bits)
      rsaTwo.createRSAPublic(privateKey.n, undefined)
    } catch (error) {
      errorMessage = error.message
    }
    // Assert
    expect(errorMessage).not.to.be.eq(null)
  })

  it('FAIL: create public key with invalid n', () => {
    // Arrange
    let errorMessage = null
    // Act
    try {
      const privateKeys = rsaOne.generateRSAPrivate(bits)
      rsaTwo.createRSAPublic(undefined, privateKeys.e)
    } catch (error) {
      errorMessage = error.message
    }
    // Assert
    expect(errorMessage).not.to.be.eq(null)
  })

  it('OK: get private key', () => {
    // Act
    rsaOne.generateRSAPrivate(bits)
    const key = rsaOne.getRSAPrivate()
    // Assert
    expect(key).to.have.property('n')
    expect(key).to.have.property('d')
    expect(key).to.have.property('e')
    expect(key.e.length).to.be.least(1)
    expect(key.n.length).to.be.least(1)
    expect(key.d.length).to.be.least(1)
    expect(Number(key.e)).not.to.be.eq(NaN)
    expect(Number(key.e)).to.be.eq(10001)
  })

  it('FAIL: get private key with not created', () => {
    // Arrange
    let errorMessage = null
    // Act
    try {
      rsaOne.getRSAPrivate()
    } catch (error) {
      errorMessage = error.message
    }
    // Assert
    expect(errorMessage).not.to.be.eq(null)
  })

  it('OK: get public key', () => {
    // Act
    const privateKey = rsaOne.generateRSAPrivate(bits)
    rsaTwo.createRSAPublic(privateKey.n, privateKey.e)
    const publicKey = rsaTwo.getRSAPublic()
    // Assert
    expect(publicKey).to.have.property('n')
    expect(publicKey).to.have.property('e')
    expect(publicKey.e.length).to.be.least(1)
    expect(publicKey.n.length).to.be.least(1)
    expect(Number(publicKey.e)).not.to.be.eq(NaN)
  })

  it('FAIL: get public key with not created', () => {
    // Arrange
    let errorMessage = null
    // Act
    try {
      rsaTwo.getRSAPublic()
    } catch (error) {
      errorMessage = error.message
    }
    // Assert
    expect(errorMessage).not.to.be.eq(null)
  })

  it('OK: generate private key from n, d, e and primes', () => {
    // Act
    const { n, d, e, primes } = rsaOne.generateRSAPrivate(1024)
    const rsaFrom = rsaTwo.generateRSAPrivateFrom(n, d, e, primes)
    const sign = rsaTwo.signMessage('sign message rsa in created instance with params')
    // Assert
    expect(sign).to.be.a('string')
    expect(sign.length).to.be.least(0)
    expect(rsaFrom).to.have.property('d')
    expect(rsaFrom).to.have.property('n')
    expect(rsaFrom).to.have.property('e')
    expect(rsaFrom).to.have.property('primes')
    expect(rsaFrom.n).to.be.equal(n)
    expect(rsaFrom.d).to.be.equal(d)
  })

  it('FAIL: generate rsa from key with invalid d', () => {
    // Arrange
    let errorMessage = null
    // Act
    try {
      const { n, e, primes } = rsaOne.generateRSAPrivate(1024)
      rsaTwo.generateRSAPrivateFrom(n, undefined, e, primes)
    } catch (error) {
      errorMessage = error.message
    }
    // Assert
    expect(errorMessage).not.to.be.eq(null)
  })

  it('FAIL: generate rsa from key with invalid n', () => {
    // Arrange
    let errorMessage = null
    // Act
    try {
      const { d, e, primes } = rsaOne.generateRSAPrivate(1024)
      rsaTwo.generateRSAPrivateFrom(undefined, d, e, primes)
    } catch (error) {
      errorMessage = error.message
    }
    // Assert
    expect(errorMessage).not.to.be.eq(null)
  })

  it('FAIL: generate rsa from key with invalid e', () => {
    // Arrange
    let errorMessage = null
    // Act
    try {
      const { d, n, primes } = rsaOne.generateRSAPrivate(1024)
      rsaTwo.generateRSAPrivateFrom(n, d, undefined, primes)
    } catch (error) {
      errorMessage = error.message
    }
    // Assert
    expect(errorMessage).not.to.be.eq(null)
  })

  it('FAIL: generate rsa from key with invalid primes', () => {
    // Arrange
    let errorMessage = null
    // Act
    try {
      const { d, n, e } = rsaOne.generateRSAPrivate(1024)
      rsaTwo.generateRSAPrivateFrom(n, d, e, undefined)
    } catch (error) {
      errorMessage = error.message
    }
    // Assert
    expect(errorMessage).not.to.be.eq(null)
  })

  it('FAIL: generate rsa from key with empty primes', () => {
    // Arrange
    let errorMessage = null
    // Act
    try {
      const { d, n, e } = rsaOne.generateRSAPrivate(1024)
      rsaTwo.generateRSAPrivateFrom(n, d, e, [])
    } catch (error) {
      errorMessage = error.message
    }
    // Assert
    expect(errorMessage).not.to.be.eq(null)
  })

  it('OK: generate private rsa key from key and back', () => {
    // Arrange
    const privatePEM = `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDD/UjzFPIp85KE
Ga4rhPYY0/8MszqrNHcyoogVXyg5MTXCee6nQPOk88HLsDM2KW7JBtvc2LDbzPVm
P6ZxqRsj03T3VrC4YOari460Jn9J6L4ueKvUagkxxF2XyaB7yuoblFmuTsZA98Zj
wAgfPA4G2PaeaxtdzWWXV4ehmGoXslKFzNnMSBLu/a+GROrWTT/5vg1jybXrppeD
cTeBBE+vbcv9k/Al7j6eIwCi0ObZYoEEET+3Et5hGv6w7qrH+Ds0MBhesSMmVLSm
vkEMaJxUcWGnIQazgghFjnFvnQkF57zJsMl/sTjm7QkA9IIxejPGvfgARbP1aAAv
UMtjpoULAgMBAAECggEABYwix3adUCCr0f9kFalCyfseKf7ct0HZ6d392hUCb3P8
IJAQ+Dz3aIDZyGkpWewcTaZbDMo5X09S1t0QWgE+Wmo+0k1q3R0pCkv98w1v5uim
kWwq+O0za2wydfxoBXj93V/6ldt28xnQTLx/vlqVzw3PFTbU5HfO21TH6wQEZL1D
rhEshddoU9a9qrqzsVFNLUiGHAvMR7YijagLl0t2LMSfeIt5qS4Rj7fCyXGzNNSx
01h31IfVSUT1FdWTf+fRAYF20nupqejzLjRc5srNoTrQnK7otDFYFxiwb/E2/Dte
I6kIr5SgscOBoQizBPL/yINgWjWHYUrMRyX+EN2sqQKBgQDOtX4Zs4QDNFT7otjL
D1JNIY6bcic0P86XMq6LNSV5o6JmxNDMlPD/EjVAicjOxn1LYbnzIQyuzOVrNXm0
+QA8dsJMyQzzNO7o6t9lLtrG+CXBKP7wmVBb8mMWve0VKNeLZyOpbOamGC1P7mPp
JVoRh+8DAVzKPXlEaKXXLasZHwKBgQDyuWs8b/6wv1d8WGZoXYuCkL1l/ywNidZP
AeBys4FXdqN6luOuCIoMpu7sOzCT7exu5pz3toB74bwVGRsSlcp3LJirb8LN4U3o
jkD3Tp8Gn7f7pUE43ZphU8B25ebAMBgCC5V+77HVIlo8GmLFz0M5XAslWtZ6GMmr
XF3HhERalQKBgEejfN15aqIVq/I94PaXC8XxgFP9PvsLthSOmxFhzOgYPvtw8JBG
ejNcYxpH5lFLVzcd2m0ZoiSenFAIi3Kd7WgHHJWyBAvx527Pn7aYg3f7nlIQXDKU
X9ZN7et+zUDNE86bYy+fr1wW+vU9wGCX8lwrCTm4aikpHvMHdZpamHavAoGADYSq
JkmOg8WEV9aMjY94L6NkCQQ3LeHZX7kZCQpaT8a5wCAbOhwbpCy/7cQ2Jmb/3gVW
BK3TZhLiaMJnMZfKGO0Q66tjzBeaQTN7BssILFRE6O0BPuuIp5cEhxqyyU1kaOjA
QLuUyewJ3oMRsTaj5dPsgv4WJ+KtiK+yQWRqcikCgYAwRzXzsrGK2HpkER3sEXok
hydDHbuqKLuT2Cqe6wyBpJPq5MyMu/T7ANmAPtJK4nvQF5RQoGdTne6/lvvwNMf2
ullviEZz1ehunkmoU25CgAKLXXCMmw/T8GyX6UUIqofyFGHasj/vjA8ZIpdLyKVP
khSri8NDQTao0i43teKIMA==
-----END PRIVATE KEY-----
`
    // Act
    const key = rsaOne.createRSAPrivateFromPEM(privatePEM)
    const generatedPEM = rsaOne.privateKeyToPEM()
    // Assert
    expect(key).to.have.property('n')
    expect(key).to.have.property('d')
    expect(key).to.have.property('e')
    expect(key.e.length).to.be.least(1)
    expect(key.n.length).to.be.least(1)
    expect(key.d.length).to.be.least(1)
    expect(Number(key.e)).not.to.be.eq(NaN)
    expect(Number(key.e)).to.be.eq(10001)
    expect(generatedPEM).to.be.eq(privatePEM)
  })

  it('FAIL: generate private rsa key from pem with invalid pem', () => {
    // Arrange
    const invalidPEM = 'invalid_pem'
    let errorMessage = null
    // Act
    try {
      rsaOne.createRSAPrivateFromPEM(invalidPEM)
    } catch (error) {
      errorMessage = error.message
    }
    // Assert
    expect(errorMessage).not.to.be.eq(null)
  })

  it('FAIL: get private rsa key pem without key create', () => {
    // Arrange
    const invalidPEM = 'invalid_pem'
    let errorMessage = null
    // Act
    try {
      rsaOne.privateKeyToPEM(invalidPEM)
    } catch (error) {
      errorMessage = error.message
    }
    // Assert
    expect(errorMessage).not.to.be.eq(null)
  })

  it('OK: generate public rsa key from pem and back', () => {
    // Arrange
    const publicPEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw/1I8xTyKfOShBmuK4T2
GNP/DLM6qzR3MqKIFV8oOTE1wnnup0DzpPPBy7AzNiluyQbb3Niw28z1Zj+mcakb
I9N091awuGDmq4uOtCZ/Sei+Lnir1GoJMcRdl8mge8rqG5RZrk7GQPfGY8AIHzwO
Btj2nmsbXc1ll1eHoZhqF7JShczZzEgS7v2vhkTq1k0/+b4NY8m166aXg3E3gQRP
r23L/ZPwJe4+niMAotDm2WKBBBE/txLeYRr+sO6qx/g7NDAYXrEjJlS0pr5BDGic
VHFhpyEGs4IIRY5xb50JBee8ybDJf7E45u0JAPSCMXozxr34AEWz9WgAL1DLY6aF
CwIDAQAB
-----END PUBLIC KEY-----
`
    // Act
    const key = rsaTwo.createRSAPublicFromPEM(publicPEM)
    const generatedPEM = rsaTwo.publicKeyToPEM()
    // Assert
    expect(key).to.have.property('n')
    expect(key).to.have.property('e')
    expect(key.e.length).to.be.least(1)
    expect(key.n.length).to.be.least(1)
    expect(Number(key.e)).not.to.be.eq(NaN)
    expect(Number(key.e)).to.be.eq(10001)
    expect(generatedPEM).to.be.eq(publicPEM)
  })

  it('FAIL: generate public rsa key from pem with invalid pem', () => {
    // Arrange
    const invalidPEM = 'invalid_pem'
    let errorMessage = null
    // Act
    try {
      rsaTwo.createRSAPublicFromPEM(invalidPEM)
    } catch (error) {
      errorMessage = error.message
    }
    // Assert
    expect(errorMessage).not.to.be.eq(null)
  })

  it('FAIL: get public rsa key pem without key create', () => {
    // Arrange
    const invalidPEM = 'invalid_pem'
    let errorMessage = null
    // Act
    try {
      rsaTwo.publicKeyToPEM(invalidPEM)
    } catch (error) {
      errorMessage = error.message
    }
    // Assert
    expect(errorMessage).not.to.be.eq(null)
  })
})
