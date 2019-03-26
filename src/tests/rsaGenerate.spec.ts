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
    expect(Number(keys.e)).to.be.eq(10001)
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

  it('generate private keys from n, d, e and primes', () => {
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

  it('generate rsa from keys with invalid d', () => {
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

  it('generate rsa from keys with invalid n', () => {
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

  it('generate rsa from keys with invalid e', () => {
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

  it('generate rsa from keys with invalid primes', () => {
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

  it('generate rsa from keys with empty primes', () => {
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
})
