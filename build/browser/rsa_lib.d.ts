/* tslint:disable */
export class RSAPrivateKeyPair {
free(): void;

 constructor();

 generate(arg0: number): void;

 sign_message(arg0: string): string;

 get_e(): string;

 get_d(): string;

 get_n(): string;

}
export class RSAPublicKeyPair {
free(): void;

 constructor();

 create(arg0: string, arg1: string): void;

 verify_message(arg0: string, arg1: string): boolean;

 get_e(): string;

 get_n(): string;

}
