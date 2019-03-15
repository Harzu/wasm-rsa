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

  it('Generate private key pair', () => {
    // Act
    const keys = rsaOne.generateRSAPrivate(bits)
    // Assert
    expect(keys).to.have.property('n')
    expect(keys).to.have.property('d')
    expect(keys).to.have.property('e')
    expect(keys.e.length).to.be.least(1)
    expect(keys.n.length).to.be.least(1)
    expect(keys.d.length).to.be.least(1)
    expect(Number(keys.e)).not.to.be.eq(NaN)
  })

  it('Generate another keys', () => {
    // Act
    const keysFirst = rsaOne.generateRSAPrivate(bits)
    const keysSecond = rsaOne.generateRSAPrivate(bits)
    // Assert
    expect(keysFirst.d).not.to.be.equal(keysSecond.d)
    expect(keysFirst.n).not.to.be.equal(keysSecond.n)
  })

  it('Generate private key pair with invalid bits', () => {
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

  it('Create public keys', () => {
    // Act
    const { n, e } = rsaOne.generateRSAPrivate(bits)
    const publicKeys = rsaTwo.createRSAPublic(n, e)
    // Assert
    expect(publicKeys).to.have.property('n')
    expect(publicKeys).to.have.property('e')
    expect(publicKeys.e.length).to.be.least(1)
    expect(publicKeys.n.length).to.be.least(1)
    expect(Number(publicKeys.e)).not.to.be.eq(NaN)
  })

  it('Create public keys with invalid e', () => {
    // Arrange
    let errorMessage = null
    // Act
    try {
      const privateKeys = rsaOne.generateRSAPrivate(bits)
      rsaTwo.createRSAPublic(privateKeys.n, undefined)
    } catch (error) {
      errorMessage = error.message
    }
    // Assert
    expect(errorMessage).not.to.be.eq(null)
  })

  it('Create public keys with invalid n', () => {
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

  it('Get private keys', () => {
    // Act
    rsaOne.generateRSAPrivate(bits)
    const keys = rsaOne.getRSAPrivate()
    // Assert
    expect(keys).to.have.property('n')
    expect(keys).to.have.property('d')
    expect(keys).to.have.property('e')
    expect(keys.e.length).to.be.least(1)
    expect(keys.n.length).to.be.least(1)
    expect(keys.d.length).to.be.least(1)
    expect(Number(keys.e)).not.to.be.eq(NaN)
    expect(Number(keys.e)).to.be.eq(2001)
  })

  it('Get private keys with not created', () => {
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

  it('Get public keys', () => {
    // Act
    const privateKeys = rsaOne.generateRSAPrivate(bits)
    rsaTwo.createRSAPublic(privateKeys.n, privateKeys.e)
    const publicKeys = rsaTwo.getRSAPublic()
    // Assert
    expect(publicKeys).to.have.property('n')
    expect(publicKeys).to.have.property('e')
    expect(publicKeys.e.length).to.be.least(1)
    expect(publicKeys.n.length).to.be.least(1)
    expect(Number(publicKeys.e)).not.to.be.eq(NaN)
  })

  it('Get public keys with not created', () => {
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
})
