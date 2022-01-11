import 'mocha'
import RSASetup from '../index.node'
import { expect } from 'chai'

let rsaOne = null
let rsaTwo = null

describe('RSA sign/verify', () => {
  beforeEach(async () => {
    rsaOne = await RSASetup()
    rsaTwo = await RSASetup()

    const privateKey = rsaOne.generateRSAPrivate(1024)
    rsaTwo.createRSAPublic(privateKey.n, privateKey.e)
  })

  it('OK: sign message', () => {
    // Arrange
    const message = 'Hello'
    // Act
    const signature = rsaOne.signMessage(message)
    // Assert
    expect(signature).to.be.a('string')
    expect(signature.length).to.be.least(1)
  })

  it('FAIL: sign message with invalid', () => {
    // Arrange
    let errorMessage = null
    const message = 12345
    // Act
    try {
      rsaOne.signMessage(message)
    } catch (error) {
      errorMessage = error.message
    }
    // Assert
    expect(errorMessage).not.to.be.eq(null)
  })

  it('OK: verify message', () => {
    // Arrange
    const message = 'Hello'
    // Act
    const signature = rsaOne.signMessage(message)
    const verify = rsaTwo.verify(message, signature)
    // Assert
    expect(verify).to.be.a('boolean')
    expect(verify).to.be.eq(true)
  })

  it('FAIL: verify message with invalid message', () => {
    // Arrange
    let errorMessage = null
    const message = 'Hello'
    // Act
    try {
      const signature = rsaOne.signMessage(message)
      rsaTwo.verify('Bye', signature)
    } catch (error) {
      errorMessage = error.message
    }
    // Assert
    expect(errorMessage).not.to.be.eq(null)
  })

  it('FAIL: verify with invalid signature', () => {
    // Arrange
    let errorMessage = null
    const message = 'Hello'
    const invalidMessage = 'Bye'
    // Act
    try {
      const invalidSignature = rsaOne.signMessage(invalidMessage)
      rsaTwo.verify(message, invalidSignature)
    } catch (error) {
      errorMessage = error.message
    }
    // Assert
    expect(errorMessage).not.to.be.eq(null)
  })
})
