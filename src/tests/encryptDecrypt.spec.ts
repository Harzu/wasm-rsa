import 'mocha'
import RSASetup from '../index.node'
import { expect } from 'chai'

let rsaOne = null
let rsaTwo = null

describe('RSA encrypt/decrypt', () => {
  beforeEach(async () => {
    rsaOne = await RSASetup()
    rsaTwo = await RSASetup()

    const privateKeys = rsaOne.generateRSAPrivate(1024)
    rsaTwo.createRSAPublic(privateKeys.n, privateKeys.e)
  })

  it('encrypt message', () => {
    // Arrange
    const message = 'hello world!'
    // Act
    const encryptedMessage = rsaTwo.publicEncrypt(message)
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
})
