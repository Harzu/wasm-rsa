use super::*;
use sha2::{ Digest };
use rsa::{ PublicKey, pkcs8::FromPublicKey };

#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct RSAPublicKeyPair {
    n: String,
    e: String,
    public_instance: Option<RsaPublicKey>
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

        let pub_keys = RsaPublicKey::new(bn_n, bn_e).expect("invalid create public instance");

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
                    PaddingScheme::new_pkcs1v15_encrypt(),
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
                PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA2_256)),
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

    pub fn to_pkcs8_pem(&self) -> String {
        utils::set_panic_hook();
        match &self.public_instance {
            Some(keys) => {
                let pem = keys.to_public_key_pem().expect("failed to generate public key pem format");
                pem.to_string()
            }
            None => panic!("Instance not created")
        }
    }

    pub fn from_pkcs8_pem(&mut self, data: &str) {
        utils::set_panic_hook();
        let keys = RsaPublicKey::from_public_key_pem(data).expect("failed to parse public key");
        self.n = keys.n().to_str_radix(16);
        self.e = keys.e().to_str_radix(16);
        self.public_instance = Some(keys);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    mod create {
        use super::*;

        #[test]
        fn create_keys() {
            let seed = "c993abb954f4ad796efa851ce4276f12250633ec4a8da1d1c8f37a82b633c1b7";
            let mut public_instance = RSAPublicKeyPair::new();
            let mut private_instance = private_keys::RSAPrivateKeyPair::new();
            private_instance.generate(1024, seed);
            public_instance.create(&private_instance.get_n(), &private_instance.get_e());
            assert_ne!(public_instance.get_e(), "".to_string());
            assert_ne!(public_instance.get_n(), "".to_string());
        }
    
        #[test]
        #[should_panic]
        fn create_keys_without_n() {
            let seed = "c993abb954f4ad796efa851ce4276f12250633ec4a8da1d1c8f37a82b633c1b7";
            let mut public_instance = RSAPublicKeyPair::new();
            let mut private_instance = private_keys::RSAPrivateKeyPair::new();
            private_instance.generate(1024, seed);
            public_instance.create("", &private_instance.get_e());
        }
    
        #[test]
        #[should_panic]
        fn create_keys_without_e() {
            let seed = "c993abb954f4ad796efa851ce4276f12250633ec4a8da1d1c8f37a82b633c1b7";
            let mut public_instance = RSAPublicKeyPair::new();
            let mut private_instance = private_keys::RSAPrivateKeyPair::new();
            private_instance.generate(1024, seed);
            public_instance.create(&private_instance.get_n(), "");
        }

        #[test]
        fn convert_pem_to_keys_and_back() {
            let expected_pem = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw/1I8xTyKfOShBmuK4T2
GNP/DLM6qzR3MqKIFV8oOTE1wnnup0DzpPPBy7AzNiluyQbb3Niw28z1Zj+mcakb
I9N091awuGDmq4uOtCZ/Sei+Lnir1GoJMcRdl8mge8rqG5RZrk7GQPfGY8AIHzwO
Btj2nmsbXc1ll1eHoZhqF7JShczZzEgS7v2vhkTq1k0/+b4NY8m166aXg3E3gQRP
r23L/ZPwJe4+niMAotDm2WKBBBE/txLeYRr+sO6qx/g7NDAYXrEjJlS0pr5BDGic
VHFhpyEGs4IIRY5xb50JBee8ybDJf7E45u0JAPSCMXozxr34AEWz9WgAL1DLY6aF
CwIDAQAB
-----END PUBLIC KEY-----
";

            let mut instance = RSAPublicKeyPair::new();
            instance.from_pkcs8_pem(expected_pem);
            let actual_pem = instance.to_pkcs8_pem();
            assert_eq!(expected_pem, actual_pem)
        }

        #[test]
        fn generate_pem_from_new_keys() {
            let seed = "c993abb954f4ad796efa851ce4276f12250633ec4a8da1d1c8f37a82b633c1b7";
            let mut public_instance = RSAPublicKeyPair::new();
            let mut private_instance = private_keys::RSAPrivateKeyPair::new();
            private_instance.generate(1024, seed);
            public_instance.create(&private_instance.get_n(), &private_instance.get_e());
            let public_pem = public_instance.to_pkcs8_pem();
            assert_ne!(public_pem, "".to_string());
        }

        #[test]
        #[should_panic]
        fn failed_generate_pem_instance_not_created() {
            RSAPublicKeyPair::new().to_pkcs8_pem();
        }

        #[test]
        #[should_panic]
        fn failed_create_instance_from_pem() {
            let invalid_pem = "invalid_pem";
            let mut instance = RSAPublicKeyPair::new();
            instance.from_pkcs8_pem(invalid_pem);
        }
    }

    mod encrypt {
        use super::*;

        #[test]
        fn encrypt_message() {
            let message = "hello";
            let seed = "c993abb954f4ad796efa851ce4276f12250633ec4a8da1d1c8f37a82b633c1b7";
            let mut public_instance = RSAPublicKeyPair::new();
            let mut private_instance = private_keys::RSAPrivateKeyPair::new();
            private_instance.generate(1024, seed);
            public_instance.create(&private_instance.get_n(), &private_instance.get_e());
            let encrypted_message = public_instance.encrypt(message, seed);
            assert_ne!(encrypted_message, "".to_string());
        }
    
        #[test]
        fn encrypt_message_with_empty_string() {
            let message = "";
            let seed = "c993abb954f4ad796efa851ce4276f12250633ec4a8da1d1c8f37a82b633c1b7";
            let mut public_instance = RSAPublicKeyPair::new();
            let mut private_instance = private_keys::RSAPrivateKeyPair::new();
            private_instance.generate(1024, seed);
            public_instance.create(&private_instance.get_n(), &private_instance.get_e());
            let encrypted_message = public_instance.encrypt(message, seed);
            assert_ne!(encrypted_message, "".to_string());
        }
    
        #[test]
        #[should_panic]
        fn encrypt_message_without_seed() {
            let message = "hello";
            let seed = "c993abb954f4ad796efa851ce4276f12250633ec4a8da1d1c8f37a82b633c1b7";
            let mut public_instance = RSAPublicKeyPair::new();
            let mut private_instance = private_keys::RSAPrivateKeyPair::new();
            private_instance.generate(1024, seed);
            public_instance.create(&private_instance.get_n(), &private_instance.get_e());
            public_instance.encrypt(message, "");
        }
    
        #[test]
        #[should_panic]
        fn encrypt_message_without_keys() {
            let message = "hello";
            let seed = "c993abb954f4ad796efa851ce4276f12250633ec4a8da1d1c8f37a82b633c1b7";
            let public_instance = RSAPublicKeyPair::new();
            public_instance.encrypt(message, seed);
        }
    }

    mod verify {
        use super::*;

        #[test]
        fn verify_message() {
            let message = "c993abb954f4ad796efa851ce4276f12250633ec4a8da1d1c8f37a82b633c1b7";
            let seed = "c993abb954f4ad796efa851ce4276f12250633ec4a8da1d1c8f37a82b633c1b7";
            let mut public_instance = RSAPublicKeyPair::new();
            let mut private_instance = private_keys::RSAPrivateKeyPair::new();
            private_instance.generate(1024, seed);
            public_instance.create(&private_instance.get_n(), &private_instance.get_e());
            let signature = private_instance.sign_message(message);  
            let verify = public_instance.verify_message(message, &signature);
            assert_eq!(verify, true);
        }
    
        #[test]
        fn verify_message_with_invalid_message() {
            let message = "c993abb954f4ad796efa851ce4276f12250633ec4a8da1d1c8f37a82b633c1b7";
            let seed = "c993abb954f4ad796efa851ce4276f12250633ec4a8da1d1c8f37a82b633c1b7";
            let mut public_instance = RSAPublicKeyPair::new();
            let mut private_instance = private_keys::RSAPrivateKeyPair::new();
            private_instance.generate(1024, seed);
            public_instance.create(&private_instance.get_n(), &private_instance.get_e());
            let signature = private_instance.sign_message(message);  
            let verify = public_instance.verify_message("invalid_message", &signature);
            assert_eq!(verify, false);  
        }
    
        #[test]
        fn verify_message_with_invalid_signature() {
            let message = "c993abb954f4ad796efa851ce4276f12250633ec4a8da1d1c8f37a82b633c1b7";
            let seed = "c993abb954f4ad796efa851ce4276f12250633ec4a8da1d1c8f37a82b633c1b7";
            let mut public_instance = RSAPublicKeyPair::new();
            let mut private_instance = private_keys::RSAPrivateKeyPair::new();
            private_instance.generate(1024, seed);
            public_instance.create(&private_instance.get_n(), &private_instance.get_e());
            let verify = public_instance.verify_message(message, "c993abb954f4ad796efa851ce4276f12250633ec4a8da1d1c8f37a82b633c1b7");
            assert_eq!(verify, false);  
        }
    
        #[test]
        #[should_panic]
        fn verify_message_with_invalid_signature_length() {
            let message = "c993abb954f4ad796efa851ce4276f12250633ec4a8da1d1c8f37a82b633c1b7";
            let seed = "c993abb954f4ad796efa851ce4276f12250633ec4a8da1d1c8f37a82b633c1b7";
            let mut public_instance = RSAPublicKeyPair::new();
            let mut private_instance = private_keys::RSAPrivateKeyPair::new();
            private_instance.generate(1024, seed);
            public_instance.create(&private_instance.get_n(), &private_instance.get_e());
            public_instance.verify_message(message, "c993abb");
        }
    
        #[test]
        #[should_panic]
        fn verify_message_with_nonhex_signature() {
            let message = "c993abb954f4ad796efa851ce4276f12250633ec4a8da1d1c8f37a82b633c1b7";
            let seed = "c993abb954f4ad796efa851ce4276f12250633ec4a8da1d1c8f37a82b633c1b7";
            let mut public_instance = RSAPublicKeyPair::new();
            let mut private_instance = private_keys::RSAPrivateKeyPair::new();
            private_instance.generate(1024, seed);
            public_instance.create(&private_instance.get_n(), &private_instance.get_e());
            public_instance.verify_message(message, "hello");
        }
    
        #[test]
        #[should_panic]
        fn verify_message_without_keys() {
            let message = "c993abb954f4ad796efa851ce4276f12250633ec4a8da1d1c8f37a82b633c1b7";
            let seed = "c993abb954f4ad796efa851ce4276f12250633ec4a8da1d1c8f37a82b633c1b7";
            let public_instance = RSAPublicKeyPair::new();
            let mut private_instance = private_keys::RSAPrivateKeyPair::new();
            private_instance.generate(1024, seed);
            let signature = private_instance.sign_message(message);
            public_instance.verify_message(message, &signature);
        }
    }
}