extern crate rsa;
extern crate hex;
extern crate sha2;
extern crate rand;
extern crate cfg_if;
extern crate web_sys;
extern crate wasm_bindgen;
extern crate num_bigint_dig as num_bigint;

mod utils;
use cfg_if::cfg_if;

use sha2::{ Digest, Sha256 };

use wasm_bindgen::prelude::*;

use rand::prelude::*;
use rand::{ SeedableRng };

use rsa::hash::Hashes;
use rsa::padding::PaddingScheme;
use rsa::{ RSAPrivateKey, RSAPublicKey, PublicKey };

use num_bigint::{ BigUint };

cfg_if! {
    if #[cfg(feature = "wee_alloc")] {
        extern crate wee_alloc;
        #[global_allocator]
        static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;
    }
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct RSAPrivateKeyPair {
    n: String,
    d: String,
    e: String,
    rsa_instance: Option<RSAPrivateKey>
}

#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct RSAPublicKeyPair {
    n: String,
    e: String,
    rsa_instance: Option<RSAPublicKey>
}

#[wasm_bindgen]
impl RSAPrivateKeyPair {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        RSAPrivateKeyPair {
            n: "".to_string(),
            e: "".to_string(),
            d: "".to_string(),
            rsa_instance: None
        }
    }

    pub fn generate(&mut self, bits: usize, random_seed: &str) {
        let mut seed_array: [u8; 32] = [0; 32];
        let decode_seed = hex::decode(random_seed).unwrap();
        seed_array.copy_from_slice(&decode_seed.as_slice());
        
        let mut rng: StdRng = SeedableRng::from_seed(seed_array);
        let keys = rsa::RSAPrivateKey::new(&mut rng, bits).unwrap();

        self.n = keys.n().to_str_radix(16);
        self.d = keys.d().to_str_radix(16);
        self.e = keys.e().to_str_radix(16);
        self.rsa_instance = Some(keys);
    }

    pub fn sign_message(&self, message: &str) -> String {
        let digest = Sha256::digest(message.as_bytes()).to_vec();
        match &self.rsa_instance {
            Some(instance) => {
                let sign = instance.sign(
                    PaddingScheme::PKCS1v15,
                    Some(&Hashes::SHA256),
                    &digest
                ).unwrap();

                hex::encode(&sign)
            },
            None => panic!("Instance not created")
        }
    }

    pub fn get_e(&self) -> String {
        self.e.clone()
    }

    pub fn get_d(&self) -> String {
        self.d.clone()
    }

    pub fn get_n(&self) -> String {
        self.n.clone()
    }
}

#[wasm_bindgen]
impl RSAPublicKeyPair {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        RSAPublicKeyPair {
            n: "".to_string(),
            e: "".to_string(),
            rsa_instance: None
        }
    }

    pub fn create(&mut self, n: &str, e: &str) {
        let bn_e = BigUint::parse_bytes(e.as_bytes(), 16).unwrap();
        let bn_n = BigUint::parse_bytes(n.as_bytes(), 16).unwrap();

        let pub_keys = RSAPublicKey::new(bn_n, bn_e).unwrap();

        self.n = pub_keys.n().to_str_radix(16);
        self.e = pub_keys.e().to_str_radix(16);
        self.rsa_instance = Some(pub_keys);
    }

    pub fn verify_message(&self, message: &str, signature: &str) -> bool {
        let decode_signature = hex::decode(signature).unwrap();
        let hash_mess = Sha256::digest(message.as_bytes());
        
        if let Some(instance) = &self.rsa_instance {
            return match instance.verify(
                PaddingScheme::PKCS1v15,
                Some(&Hashes::SHA256),
                &hash_mess,
                &decode_signature
            ) {
                Ok(_) => true,
                Err(_) => false
            }
        }

        panic!("Instance not created")
    }

    pub fn get_e(&self) -> String {
        self.e.clone()
    }

    pub fn get_n(&self) -> String {
        self.n.clone()
    }
}