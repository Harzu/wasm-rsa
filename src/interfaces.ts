export interface RSAPrivateKeyInterface {
  free(): void
  generate(bits: number, random: string): void
  sign_message(message: string): string
  get_e(): string
  get_d(): string
  get_n(): string
}

export interface RSAPublicKeyInterface {
  free(): void
  create(n: string, e: string): void
  verify_message(message: string, signature: string): boolean
  get_e(): string
  get_n(): string
}

export interface RSAPublic {
  n: string
  e: string
}

export interface RSAPrivate extends RSAPublic {
  d: string
}

export interface RSAInterface {
  generateRSAPrivate(bits: number): RSAPrivate
  createRSAPublic(n: string, e: string): RSAPublic

  getRSAPrivate(): RSAPrivate
  getRSAPublic(): RSAPublic

  signMessage(message: string): string
  verify(message: string, signature: string): boolean
}
