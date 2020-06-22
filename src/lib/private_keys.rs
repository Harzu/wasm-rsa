use super::*;
use sha2::{ Digest };
use num_traits::{ Num };

#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct RSAPrivateKeyPair {
    n: String,
    d: String,
    e: String,
    private_instance: Option<RSAPrivateKey>
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
        utils::set_panic_hook();
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
        utils::set_panic_hook();
        let parse_primes = primes.split("_").collect::<Vec<&str>>();
        let mut primes_vec = vec![];
        for prime in parse_primes {
            match BigUint::from_str_radix(&prime, 10) {
                Ok(result) => primes_vec.push(result),
                Err(_) => panic!("error with convert to biguint {}", prime) 
            }
        }
        
        let keys = RSAPrivateKey::from_components(
            BigUint::from_str_radix(n, 16).expect("invalid n"),
            BigUint::from_str_radix(e, 16).expect("invalid e"),            
            BigUint::from_str_radix(d, 16).expect("invalid d"),
            primes_vec
        );

        self.n = keys.n().to_str_radix(16);
        self.d = keys.d().to_str_radix(16);
        self.e = keys.e().to_str_radix(16);
        self.private_instance = Some(keys);
    }

    pub fn sign_message(&self, message: &str) -> String {
        utils::set_panic_hook();
        let digest = Sha256::digest(message.as_bytes()).to_vec();
        match &self.private_instance {
            Some(instance) => {
                let sign = match instance.sign(
                    PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA3_256)),
                    &digest
                ) {
                    Ok(res) => res,
                    Err(e) => panic!("sign error {}", e)
                };

                hex::encode(&sign)
            },
            None => panic!("Instance not created")
        }
    }

    pub fn decrypt(&self, ciphermessage: &str) -> String {
        utils::set_panic_hook();
        let decode_message = hex::decode(&ciphermessage).expect("invalid decode message");
        match &self.private_instance {
            Some(instance) => {
                let decrypt_message = match instance.decrypt(
                    PaddingScheme::new_pkcs1v15_encrypt(),
                    &decode_message
                ) {
                    Ok(res) => res,
                    Err(e) => panic!("decrypt error {}", e)
                };

                String::from_utf8(decrypt_message).expect("invalid parse decrypt message")
            },
            None => panic!("Instance not created")
        }
    }

    pub fn get_e(&self) -> String {
        self.e.to_string()
    }

    pub fn get_d(&self) -> String {
        self.d.to_string()
    }

    pub fn get_n(&self) -> String {
        self.n.to_string()
    }

    pub fn get_primes(&self) -> String {
        utils::set_panic_hook();
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