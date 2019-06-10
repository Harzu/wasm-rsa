use super::*;
use sha2::{ Digest };
use rsa::{ PublicKey };

#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct RSAPublicKeyPair {
    n: String,
    e: String,
    public_instance: Option<RSAPublicKey>
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
        utils::set_panic_hook();
        let bn_e = BigUint::parse_bytes(e.as_bytes(), 16).expect("invalid e");
        let bn_n = BigUint::parse_bytes(n.as_bytes(), 16).expect("invalid n");

        let pub_keys = RSAPublicKey::new(bn_n, bn_e).expect("invalid create public instance");

        self.n = pub_keys.n().to_str_radix(16);
        self.e = pub_keys.e().to_str_radix(16);
        self.public_instance = Some(pub_keys);
    }

    pub fn encrypt(&self, message: &str, random_seed: &str) -> String {
        utils::set_panic_hook();
        let mut seed_array: [u8; 32] = [0; 32];
        let decode_seed = hex::decode(random_seed).expect("invalid decode");
        seed_array.copy_from_slice(&decode_seed.as_slice());
        
        let mut rng: StdRng = SeedableRng::from_seed(seed_array);
        match &self.public_instance {
            Some(instance) => {
                let encrypt_message = match instance.encrypt(
                    &mut rng,
                    PaddingScheme::PKCS1v15,
                    message.as_bytes()
                ) {
                    Ok(res) => res,
                    Err(e) => panic!("encrypt error {}", e)
                };

                hex::encode(&encrypt_message)
            },
            None => panic!("Instance not created")
        }
    }

    pub fn verify_message(&self, message: &str, signature: &str) -> bool {
        utils::set_panic_hook();
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
        self.e.to_string()
    }

    pub fn get_n(&self) -> String {
        self.n.to_string()
    }
}