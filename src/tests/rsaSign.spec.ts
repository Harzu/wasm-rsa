import RSAInit from '../index.node'
import { expect } from 'chai'

let rsaOne = null
let rsaTwo = null

describe('RSA sign/verify', () => {
  beforeEach(() => {
    rsaOne = RSAInit()
    rsaTwo = RSAInit()

    const privateKeys = rsaOne.generateRSAPrivate(1024)
    rsaTwo.createRSAPublic(privateKeys.n, privateKeys.e)
  })

  it('Sign message', () => {
    // Arrange
    const message = 'Hello'
    // Act
    const signature = rsaOne.signMessage(message)
    // Assert
    expect(signature).to.be.a('string')
    expect(signature.length).to.be.least(1)
  })

  it('Sign message with invalid', () => {
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

  it('Verify message', () => {
    // Arrange
    const message = 'Hello'
    // Act
    const signature = rsaOne.signMessage(message)
    const verify = rsaTwo.verify(message, signature)
    // Assert
    expect(verify).to.be.a('boolean')
    expect(verify).to.be.eq(true)    
  })

  it('Verify message with invalid message', () => {
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

  it('Verify with invalid signature', () => {
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