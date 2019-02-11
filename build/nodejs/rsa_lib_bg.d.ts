/* tslint:disable */
export const memory: WebAssembly.Memory;
export function __wbindgen_global_argument_ptr(): number;
export function __wbg_rsaprivatekeypair_free(a: number): void;
export function __wbg_rsapublickeypair_free(a: number): void;
export function rsaprivatekeypair_new(): number;
export function rsaprivatekeypair_generate(a: number, b: number): void;
export function rsaprivatekeypair_sign_message(a: number, b: number, c: number, d: number): void;
export function rsaprivatekeypair_get_e(a: number, b: number): void;
export function rsaprivatekeypair_get_d(a: number, b: number): void;
export function rsaprivatekeypair_get_n(a: number, b: number): void;
export function rsapublickeypair_new(): number;
export function rsapublickeypair_create(a: number, b: number, c: number, d: number, e: number): void;
export function rsapublickeypair_verify_message(a: number, b: number, c: number, d: number, e: number): number;
export function rsapublickeypair_get_e(a: number, b: number): void;
export function rsapublickeypair_get_n(a: number, b: number): void;
export function __wbindgen_malloc(a: number): number;
export function __wbindgen_free(a: number, b: number): void;
