use sha2::{ Sha256 };
use wasm_bindgen::prelude::*;

use rand::prelude::*;
use rand::{ SeedableRng };

use rsa::hash::Hash;
use rsa::padding::PaddingScheme;
use rsa::{ RsaPrivateKey, RsaPublicKey, PublicKeyParts };
use rsa::pkcs8::{ ToPrivateKey, ToPublicKey };

use num_bigint_dig::{ BigUint };

mod utils;
pub mod public_keys;
pub mod private_keys;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}
