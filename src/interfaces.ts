export interface RSAPrivateKeyInterface {
  free(): void
  generate(bits: number, random: string): void
  sign_message(message: string): string
  decrypt(encryptMessage: string): string
  get_primes(): string
  generate_from(n: string, d: string, e: string, primes: string): void
  to_pkcs8_pem(): string
  from_pkcs8_pem(data: string): void
  get_e(): string
  get_d(): string
  get_n(): string
}

export interface RSAPublicKeyInterface {
  free(): void
  create(n: string, e: string): void
  verify_message(message: string, signature: string): boolean
  encrypt(message: string, randomSeed: string): string
  to_pkcs8_pem(): string
  from_pkcs8_pem(data: string): void
  get_e(): string
  get_n(): string
}

export interface RSAPublic {
  n: string
  e: string
}

export interface RSAPrivate extends RSAPublic {
  d: string
  primes: string[]
}

export interface RSAInterface {
  generateRSAPrivate(bits: number): RSAPrivate
  generateRSAPrivateFrom(n: string, d: string, e: string, primes: string[]): RSAPrivate
  createRSAPrivateFromPEM(key: string): RSAPrivate

  createRSAPublic(n: string, e: string): RSAPublic
  createRSAPublicFromPEM(key: string): RSAPublic

  getRSAPrivate(): RSAPrivate
  getRSAPublic(): RSAPublic
  getPrivatePrimes(): string[]

  privateKeyToPEM(): string
  publicKeyToPEM(): string

  publicEncrypt(message): String
  privateDecrypt(encryptedMessage): String

  signMessage(message: string): string
  verify(message: string, signature: string): boolean
}
