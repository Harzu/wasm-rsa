/* tslint:disable */
import * as wasm from './rsa_lib_bg';

let cachedTextEncoder = new TextEncoder('utf-8');

let cachegetUint8Memory = null;
function getUint8Memory() {
    if (cachegetUint8Memory === null || cachegetUint8Memory.buffer !== wasm.memory.buffer) {
        cachegetUint8Memory = new Uint8Array(wasm.memory.buffer);
    }
    return cachegetUint8Memory;
}

let WASM_VECTOR_LEN = 0;

function passStringToWasm(arg) {

    const buf = cachedTextEncoder.encode(arg);
    const ptr = wasm.__wbindgen_malloc(buf.length);
    getUint8Memory().set(buf, ptr);
    WASM_VECTOR_LEN = buf.length;
    return ptr;
}

let cachedTextDecoder = new TextDecoder('utf-8');

function getStringFromWasm(ptr, len) {
    return cachedTextDecoder.decode(getUint8Memory().subarray(ptr, ptr + len));
}

let cachedGlobalArgumentPtr = null;
function globalArgumentPtr() {
    if (cachedGlobalArgumentPtr === null) {
        cachedGlobalArgumentPtr = wasm.__wbindgen_global_argument_ptr();
    }
    return cachedGlobalArgumentPtr;
}

let cachegetUint32Memory = null;
function getUint32Memory() {
    if (cachegetUint32Memory === null || cachegetUint32Memory.buffer !== wasm.memory.buffer) {
        cachegetUint32Memory = new Uint32Array(wasm.memory.buffer);
    }
    return cachegetUint32Memory;
}

function freeRSAPrivateKeyPair(ptr) {

    wasm.__wbg_rsaprivatekeypair_free(ptr);
}
/**
*/
export class RSAPrivateKeyPair {

    free() {
        const ptr = this.ptr;
        this.ptr = 0;
        freeRSAPrivateKeyPair(ptr);
    }

    /**
    * @returns {}
    */
    constructor() {
        this.ptr = wasm.rsaprivatekeypair_new();
    }
    /**
    * @param {number} arg0
    * @returns {void}
    */
    generate(arg0) {
        return wasm.rsaprivatekeypair_generate(this.ptr, arg0);
    }
    /**
    * @param {string} arg0
    * @returns {string}
    */
    sign_message(arg0) {
        const ptr0 = passStringToWasm(arg0);
        const len0 = WASM_VECTOR_LEN;
        const retptr = globalArgumentPtr();
        try {
            wasm.rsaprivatekeypair_sign_message(retptr, this.ptr, ptr0, len0);
            const mem = getUint32Memory();
            const rustptr = mem[retptr / 4];
            const rustlen = mem[retptr / 4 + 1];

            const realRet = getStringFromWasm(rustptr, rustlen).slice();
            wasm.__wbindgen_free(rustptr, rustlen * 1);
            return realRet;


        } finally {
            wasm.__wbindgen_free(ptr0, len0 * 1);

        }

    }
    /**
    * @returns {string}
    */
    get_e() {
        const retptr = globalArgumentPtr();
        wasm.rsaprivatekeypair_get_e(retptr, this.ptr);
        const mem = getUint32Memory();
        const rustptr = mem[retptr / 4];
        const rustlen = mem[retptr / 4 + 1];

        const realRet = getStringFromWasm(rustptr, rustlen).slice();
        wasm.__wbindgen_free(rustptr, rustlen * 1);
        return realRet;

    }
    /**
    * @returns {string}
    */
    get_d() {
        const retptr = globalArgumentPtr();
        wasm.rsaprivatekeypair_get_d(retptr, this.ptr);
        const mem = getUint32Memory();
        const rustptr = mem[retptr / 4];
        const rustlen = mem[retptr / 4 + 1];

        const realRet = getStringFromWasm(rustptr, rustlen).slice();
        wasm.__wbindgen_free(rustptr, rustlen * 1);
        return realRet;

    }
    /**
    * @returns {string}
    */
    get_n() {
        const retptr = globalArgumentPtr();
        wasm.rsaprivatekeypair_get_n(retptr, this.ptr);
        const mem = getUint32Memory();
        const rustptr = mem[retptr / 4];
        const rustlen = mem[retptr / 4 + 1];

        const realRet = getStringFromWasm(rustptr, rustlen).slice();
        wasm.__wbindgen_free(rustptr, rustlen * 1);
        return realRet;

    }
}

function freeRSAPublicKeyPair(ptr) {

    wasm.__wbg_rsapublickeypair_free(ptr);
}
/**
*/
export class RSAPublicKeyPair {

    free() {
        const ptr = this.ptr;
        this.ptr = 0;
        freeRSAPublicKeyPair(ptr);
    }

    /**
    * @returns {}
    */
    constructor() {
        this.ptr = wasm.rsapublickeypair_new();
    }
    /**
    * @param {string} arg0
    * @param {string} arg1
    * @returns {void}
    */
    create(arg0, arg1) {
        const ptr0 = passStringToWasm(arg0);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm(arg1);
        const len1 = WASM_VECTOR_LEN;
        try {
            return wasm.rsapublickeypair_create(this.ptr, ptr0, len0, ptr1, len1);

        } finally {
            wasm.__wbindgen_free(ptr0, len0 * 1);
            wasm.__wbindgen_free(ptr1, len1 * 1);

        }

    }
    /**
    * @param {string} arg0
    * @param {string} arg1
    * @returns {boolean}
    */
    verify_message(arg0, arg1) {
        const ptr0 = passStringToWasm(arg0);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm(arg1);
        const len1 = WASM_VECTOR_LEN;
        try {
            return (wasm.rsapublickeypair_verify_message(this.ptr, ptr0, len0, ptr1, len1)) !== 0;

        } finally {
            wasm.__wbindgen_free(ptr0, len0 * 1);
            wasm.__wbindgen_free(ptr1, len1 * 1);

        }

    }
    /**
    * @returns {string}
    */
    get_e() {
        const retptr = globalArgumentPtr();
        wasm.rsapublickeypair_get_e(retptr, this.ptr);
        const mem = getUint32Memory();
        const rustptr = mem[retptr / 4];
        const rustlen = mem[retptr / 4 + 1];

        const realRet = getStringFromWasm(rustptr, rustlen).slice();
        wasm.__wbindgen_free(rustptr, rustlen * 1);
        return realRet;

    }
    /**
    * @returns {string}
    */
    get_n() {
        const retptr = globalArgumentPtr();
        wasm.rsapublickeypair_get_n(retptr, this.ptr);
        const mem = getUint32Memory();
        const rustptr = mem[retptr / 4];
        const rustlen = mem[retptr / 4 + 1];

        const realRet = getStringFromWasm(rustptr, rustlen).slice();
        wasm.__wbindgen_free(rustptr, rustlen * 1);
        return realRet;

    }
}

export function __wbindgen_throw(ptr, len) {
    throw new Error(getStringFromWasm(ptr, len));
}

