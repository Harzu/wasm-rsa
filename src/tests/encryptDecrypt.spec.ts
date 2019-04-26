import 'mocha'
import RSASetup from '../index.node'
import { expect } from 'chai'

let rsaOne = null
let rsaTwo = null
let n = null
let d = null
let e = null
let primes = null

describe('RSA encrypt/decrypt', () => {
  beforeEach(async () => {
    rsaOne = await RSASetup()
    rsaTwo = await RSASetup()

    const privateKeys = rsaOne.generateRSAPrivate(2048)
    n = privateKeys.n
    d = privateKeys.d
    e = privateKeys.e
    primes = privateKeys.primes
    rsaTwo.createRSAPublic(n, e)
  })

  it('encrypt message', () => {
    // Arrange
    const message = 'hello'
    // Act
    const encryptedMessage = rsaTwo.publicEncrypt(message)
    console.log(encryptedMessage)
    // Assert
    expect(encryptedMessage).to.be.a('string')
    expect(encryptedMessage).not.to.be.equal(message)
  })

  it('encrypt message with invalid message', () => {
    // Arrange
    let errorMessage = null
    // Act
    try {
      rsaTwo.publicEncrypt(undefined)
    } catch (error) {
      errorMessage = error.message
    }
    // Assert
    expect(errorMessage).not.to.be.equal(null)
  })

  it('decrypt message', () => {
    // Arrange
    const message = 'hello world!'
    // Act
    const encryptedMessage = rsaTwo.publicEncrypt(message)
    const decryptedMessage = rsaOne.privateDecrypt(encryptedMessage)
    // Assert
    expect(decryptedMessage).to.be.equal(message)
  })

  it('decrypt with invalid encryptedMessage', () => {
    // Arrange
    let errorMessage = null
    // Act
    try {
      rsaTwo.privateDecrypt(undefined)
    } catch (error) {
      errorMessage = error.message
    }
    // Assert
    expect(errorMessage).not.to.be.equal(null)
  })

  it('decrypt message with rsa generate from n, d, e, primes', async () => {
    // Arrange
    const message = 'hello'
    // Act
    const encryptedMessage = rsaTwo.publicEncrypt(message)
    rsaOne.generateRSAPrivateFrom(n, d, e, primes)
    const decryptedMessage = rsaOne.privateDecrypt(encryptedMessage)
    // Assert
    expect(decryptedMessage).to.be.equal(message)
  })
})
