extern crate rsa;
extern crate hex;
extern crate sha2;
extern crate rand;
extern crate cfg_if;
extern crate web_sys;
extern crate num_traits;
extern crate wasm_bindgen;
extern crate console_error_panic_hook;
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
use num_traits::{ Num };

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
    private_instance: Option<RSAPrivateKey>
}

#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct RSAPublicKeyPair {
    n: String,
    e: String,
    public_instance: Option<RSAPublicKey>
}

#[wasm_bindgen]
impl RSAPrivateKeyPair {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        RSAPrivateKeyPair {
            n: "".to_string(),
            e: "".to_string(),
            d: "".to_string(),
            private_instance: None
        }
    }

    pub fn generate(&mut self, bits: usize, random_seed: &str) {
        console_error_panic_hook::set_once();
        let mut seed_array: [u8; 32] = [0; 32];
        let decode_seed = hex::decode(random_seed).unwrap();
        seed_array.copy_from_slice(&decode_seed.as_slice());
        
        let mut rng: StdRng = SeedableRng::from_seed(seed_array);
        let keys = RSAPrivateKey::new(&mut rng, bits).unwrap();

        self.n = keys.n().to_str_radix(16);
        self.d = keys.d().to_str_radix(16);
        self.e = keys.e().to_str_radix(16);
        self.private_instance = Some(keys);
    }

    pub fn generate_from(&mut self, n: &str, d: &str, e: &str, primes: &str) {
        console_error_panic_hook::set_once();
        let parse_primes = primes.split("_").collect::<Vec<&str>>();
        let mut primes_vec = vec![];
        for prime in parse_primes {
            match BigUint::from_str_radix(&prime, 10) {
                Ok(result) => primes_vec.push(result),
                Err(_) => panic!("error with convert to biguint {}", prime) 
            }
        }

        let keys = RSAPrivateKey::from_components(
            BigUint::from_str_radix(n, 16).unwrap(),
            BigUint::from_str_radix(e, 16).unwrap(),            
            BigUint::from_str_radix(d, 16).unwrap(),
            primes_vec
        );

        self.n = keys.n().to_str_radix(16);
        self.d = keys.d().to_str_radix(16);
        self.e = keys.e().to_str_radix(16);
        self.private_instance = Some(keys);
    }

    pub fn sign_message(&self, message: &str) -> String {
        console_error_panic_hook::set_once();
        let digest = Sha256::digest(message.as_bytes()).to_vec();
        match &self.private_instance {
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

    pub fn decrypt(&self, ciphermessage: &str) -> String {
        console_error_panic_hook::set_once();
        match &self.private_instance {
            Some(instance) => {
                let decrypt_message = match instance.decrypt(
                    PaddingScheme::PKCS1v15,
                    &hex::decode(&ciphermessage).unwrap()
                ) {
                    Ok(res) => res,
                    Err(e) => panic!("error decrypt {}", e)
                };

                String::from_utf8(decrypt_message).unwrap()
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

    pub fn get_primes(&self) -> String {
        console_error_panic_hook::set_once();
        match &self.private_instance {
            Some(instance) => {
                let mut primes_string = Vec::new();
                for prime in instance.primes() {
                    primes_string.push(prime.to_str_radix(10))
                }

                primes_string.join("_")
            },
            None => panic!("Instance not created")
        }
    }
}

#[wasm_bindgen]
impl RSAPublicKeyPair {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        RSAPublicKeyPair {
            n: "".to_string(),
            e: "".to_string(),
            public_instance: None
        }
    }

    pub fn create(&mut self, n: &str, e: &str) {
        console_error_panic_hook::set_once();
        let bn_e = BigUint::parse_bytes(e.as_bytes(), 16).unwrap();
        let bn_n = BigUint::parse_bytes(n.as_bytes(), 16).unwrap();

        let pub_keys = RSAPublicKey::new(bn_n, bn_e).unwrap();

        self.n = pub_keys.n().to_str_radix(16);
        self.e = pub_keys.e().to_str_radix(16);
        self.public_instance = Some(pub_keys);
    }

    pub fn encrypt(&self, message: &str, random_seed: &str) -> String {
        console_error_panic_hook::set_once();
        let mut seed_array: [u8; 32] = [0; 32];
        let decode_seed = hex::decode(random_seed).unwrap();
        seed_array.copy_from_slice(&decode_seed.as_slice());
        
        let mut rng: StdRng = SeedableRng::from_seed(seed_array);
        match &self.public_instance {
            Some(instance) => {
                let encrypt_message = instance.encrypt(
                    &mut rng,
                    PaddingScheme::PKCS1v15,
                    message.as_bytes()
                ).unwrap();

                hex::encode(&encrypt_message)
            },
            None => panic!("Instance not created")
        }
    }

    pub fn verify_message(&self, message: &str, signature: &str) -> bool {
        console_error_panic_hook::set_once();
        let decode_signature = hex::decode(signature).unwrap();
        let hash_mess = Sha256::digest(message.as_bytes());
        
        if let Some(instance) = &self.public_instance {
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