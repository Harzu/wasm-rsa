use super::*;
use rsa::pkcs8::FromPrivateKey;
use sha2::{ Digest };
use num_traits::{ Num };

#[wasm_bindgen]
#[derive(Debug, Clone)]
pub struct RSAPrivateKeyPair {
    n: String,
    d: String,
    e: String,
    private_instance: Option<RsaPrivateKey>
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
        let keys = RsaPrivateKey::new(&mut rng, bits).unwrap();

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
        
        let keys = RsaPrivateKey::from_components(
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
                    PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA2_256)),
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

    pub fn to_pkcs8_pem(&self) -> String {
        utils::set_panic_hook();
        match &self.private_instance {
            Some(keys) => {
                let pem = keys.to_pkcs8_pem().expect("failed to generate private key pem format");
                pem.to_string()
            }
            None => panic!("Instance not created")
        }
    }

    pub fn from_pkcs8_pem(&mut self, data: &str) {
        utils::set_panic_hook();
        let keys = RsaPrivateKey::from_pkcs8_pem(data).expect("failed to parse private key");
        self.n = keys.n().to_str_radix(16);
        self.d = keys.d().to_str_radix(16);
        self.e = keys.e().to_str_radix(16);
        self.private_instance = Some(keys);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    mod generate {
        use super::*;

        #[test]
        fn generate_private_keys() {
            let seed = "c993abb954f4ad796efa851ce4276f12250633ec4a8da1d1c8f37a82b633c1b7";
            let mut instance = RSAPrivateKeyPair::new();
            instance.generate(1024, seed);
            assert_ne!(instance.get_d(), "".to_string());
            assert_ne!(instance.get_e(), "".to_string());
            assert_ne!(instance.get_n(), "".to_string());
        }
    
        #[test]
        #[should_panic]
        fn generate_private_keys_with_empty_seed() {
            let mut instance = RSAPrivateKeyPair::new();
            instance.generate(1024, "");
        }
    
        #[test]
        #[should_panic]
        fn generate_private_keys_with_zero_bits() {
            let seed = "c993abb954f4ad796efa851ce4276f12250633ec4a8da1d1c8f37a82b633c1b7";
            let mut instance = RSAPrivateKeyPair::new();
            instance.generate(0, seed);
        }
    }

    mod generate_from {
        use super::*;

        #[test]
        fn generate_rsa_private_from() {
            let seed = "c993abb954f4ad796efa851ce4276f12250633ec4a8da1d1c8f37a82b633c1b7";
            let mut first_instance = RSAPrivateKeyPair::new();
            first_instance.generate(1024, seed);
    
            let mut second_instance = RSAPrivateKeyPair::new();
            second_instance.generate_from(
                &first_instance.get_n(),
                &first_instance.get_d(),
                &first_instance.get_e(),
                &first_instance.get_primes()
            );
    
            assert_eq!(first_instance.get_n(), second_instance.get_n());
            assert_eq!(first_instance.get_d(), second_instance.get_d());
            assert_eq!(first_instance.get_e(), second_instance.get_e());
            assert_eq!(first_instance.get_primes(), second_instance.get_primes());
        }
    
        #[test]
        #[should_panic]
        fn generate_rsa_private_from_without_n() {
            let seed = "c993abb954f4ad796efa851ce4276f12250633ec4a8da1d1c8f37a82b633c1b7";
            let mut first_instance = RSAPrivateKeyPair::new();
            first_instance.generate(1024, seed);
    
            let mut second_instance = RSAPrivateKeyPair::new();
            second_instance.generate_from(
                "",
                &first_instance.get_d(),
                &first_instance.get_e(),
                &first_instance.get_primes()
            );
        }
    
        #[test]
        #[should_panic]
        fn generate_rsa_private_from_without_d() {
            let seed = "c993abb954f4ad796efa851ce4276f12250633ec4a8da1d1c8f37a82b633c1b7";
            let mut first_instance = RSAPrivateKeyPair::new();
            first_instance.generate(1024, seed);
    
            let mut second_instance = RSAPrivateKeyPair::new();
            second_instance.generate_from(
                &first_instance.get_n(),
                "",
                &first_instance.get_e(),
                &first_instance.get_primes()
            );
        }
    
        #[test]
        #[should_panic]
        fn generate_rsa_private_from_without_e() {
            let seed = "c993abb954f4ad796efa851ce4276f12250633ec4a8da1d1c8f37a82b633c1b7";
            let mut first_instance = RSAPrivateKeyPair::new();
            first_instance.generate(1024, seed);
    
            let mut second_instance = RSAPrivateKeyPair::new();
            second_instance.generate_from(
                &first_instance.get_n(),
                &first_instance.get_d(),
                "",
                &first_instance.get_primes()
            );
        }
    
        #[test]
        #[should_panic]
        fn generate_rsa_private_from_without_primes() {
            let seed = "c993abb954f4ad796efa851ce4276f12250633ec4a8da1d1c8f37a82b633c1b7";
            let mut first_instance = RSAPrivateKeyPair::new();
            first_instance.generate(1024, seed);
    
            let mut second_instance = RSAPrivateKeyPair::new();
            second_instance.generate_from(
                &first_instance.get_n(),
                &first_instance.get_d(),
                &first_instance.get_e(),
                ""
            );
        }

        #[test]
        fn convert_pem_to_keys_and_back() {
            let expected_pem = "-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDD/UjzFPIp85KE
Ga4rhPYY0/8MszqrNHcyoogVXyg5MTXCee6nQPOk88HLsDM2KW7JBtvc2LDbzPVm
P6ZxqRsj03T3VrC4YOari460Jn9J6L4ueKvUagkxxF2XyaB7yuoblFmuTsZA98Zj
wAgfPA4G2PaeaxtdzWWXV4ehmGoXslKFzNnMSBLu/a+GROrWTT/5vg1jybXrppeD
cTeBBE+vbcv9k/Al7j6eIwCi0ObZYoEEET+3Et5hGv6w7qrH+Ds0MBhesSMmVLSm
vkEMaJxUcWGnIQazgghFjnFvnQkF57zJsMl/sTjm7QkA9IIxejPGvfgARbP1aAAv
UMtjpoULAgMBAAECggEABYwix3adUCCr0f9kFalCyfseKf7ct0HZ6d392hUCb3P8
IJAQ+Dz3aIDZyGkpWewcTaZbDMo5X09S1t0QWgE+Wmo+0k1q3R0pCkv98w1v5uim
kWwq+O0za2wydfxoBXj93V/6ldt28xnQTLx/vlqVzw3PFTbU5HfO21TH6wQEZL1D
rhEshddoU9a9qrqzsVFNLUiGHAvMR7YijagLl0t2LMSfeIt5qS4Rj7fCyXGzNNSx
01h31IfVSUT1FdWTf+fRAYF20nupqejzLjRc5srNoTrQnK7otDFYFxiwb/E2/Dte
I6kIr5SgscOBoQizBPL/yINgWjWHYUrMRyX+EN2sqQKBgQDOtX4Zs4QDNFT7otjL
D1JNIY6bcic0P86XMq6LNSV5o6JmxNDMlPD/EjVAicjOxn1LYbnzIQyuzOVrNXm0
+QA8dsJMyQzzNO7o6t9lLtrG+CXBKP7wmVBb8mMWve0VKNeLZyOpbOamGC1P7mPp
JVoRh+8DAVzKPXlEaKXXLasZHwKBgQDyuWs8b/6wv1d8WGZoXYuCkL1l/ywNidZP
AeBys4FXdqN6luOuCIoMpu7sOzCT7exu5pz3toB74bwVGRsSlcp3LJirb8LN4U3o
jkD3Tp8Gn7f7pUE43ZphU8B25ebAMBgCC5V+77HVIlo8GmLFz0M5XAslWtZ6GMmr
XF3HhERalQKBgEejfN15aqIVq/I94PaXC8XxgFP9PvsLthSOmxFhzOgYPvtw8JBG
ejNcYxpH5lFLVzcd2m0ZoiSenFAIi3Kd7WgHHJWyBAvx527Pn7aYg3f7nlIQXDKU
X9ZN7et+zUDNE86bYy+fr1wW+vU9wGCX8lwrCTm4aikpHvMHdZpamHavAoGADYSq
JkmOg8WEV9aMjY94L6NkCQQ3LeHZX7kZCQpaT8a5wCAbOhwbpCy/7cQ2Jmb/3gVW
BK3TZhLiaMJnMZfKGO0Q66tjzBeaQTN7BssILFRE6O0BPuuIp5cEhxqyyU1kaOjA
QLuUyewJ3oMRsTaj5dPsgv4WJ+KtiK+yQWRqcikCgYAwRzXzsrGK2HpkER3sEXok
hydDHbuqKLuT2Cqe6wyBpJPq5MyMu/T7ANmAPtJK4nvQF5RQoGdTne6/lvvwNMf2
ullviEZz1ehunkmoU25CgAKLXXCMmw/T8GyX6UUIqofyFGHasj/vjA8ZIpdLyKVP
khSri8NDQTao0i43teKIMA==
-----END PRIVATE KEY-----
";

            let mut instance = RSAPrivateKeyPair::new();
            instance.from_pkcs8_pem(expected_pem);
            let actual_pem = instance.to_pkcs8_pem();
            assert_eq!(expected_pem, actual_pem)
        }

        #[test]
        fn generate_pem_from_new_keys() {
            let seed = "c993abb954f4ad796efa851ce4276f12250633ec4a8da1d1c8f37a82b633c1b7";
            let mut private_instance = RSAPrivateKeyPair::new();
            private_instance.generate(1024, seed);
            let private_pem = private_instance.to_pkcs8_pem();
            assert_ne!(private_pem, "".to_string());
        }

        #[test]
        #[should_panic]
        fn failed_generate_pem_instance_not_created() {
            RSAPrivateKeyPair::new().to_pkcs8_pem();
        }

        #[test]
        #[should_panic]
        fn failed_create_instance_from_pem() {
            let invalid_pem = "invalid_pem";
            let mut instance = RSAPrivateKeyPair::new();
            instance.from_pkcs8_pem(invalid_pem);
        }
    }

    mod sign {
        use super::*;

        #[test]
        fn sign_message() {
            let message = "Hello";
            let seed = "c993abb954f4ad796efa851ce4276f12250633ec4a8da1d1c8f37a82b633c1b7";
            let mut instance = RSAPrivateKeyPair::new();
            instance.generate(1024, seed);
            assert_ne!(instance.sign_message(message), "".to_string());
        }
    
        #[test]
        fn sign_message_with_long_data() {
            let message = "{ id: 'c993abb954f4ad796efa851ce4276f12250633ec4a8da1d1c8f37a82b633c1b7, id2: c993abb954f4ad796efa851ce4276f12250633ec4a8da1d1c8f37a82b633c1b7, id3: c993abb954f4ad796efa851ce4276f12250633ec4a8da1d1c8f37a82b633c1b7, id4: c993abb954f4ad796efa851ce4276f12250633ec4a8da1d1c8f37a82b633c1b7' }";
            let seed = "c993abb954f4ad796efa851ce4276f12250633ec4a8da1d1c8f37a82b633c1b7";
            let mut instance = RSAPrivateKeyPair::new();
            instance.generate(1024, seed);
            let signature = instance.sign_message(message);
            assert_ne!(signature, "".to_string());
        }
    
        #[test]
        #[should_panic]
        fn sign_message_without_keys() {
            let message = "Hello";
            let instance = RSAPrivateKeyPair::new();
            instance.sign_message(message);
        }
    
        #[test]
        fn sign_message_with_generate_keys_from_data() {
            let message = "hello";
            let seed = "c993abb954f4ad796efa851ce4276f12250633ec4a8da1d1c8f37a82b633c1b7";
            let mut private_instance = RSAPrivateKeyPair::new();
            private_instance.generate(1024, seed);
            let n = private_instance.get_n();
            let e = private_instance.get_e();
            let d = private_instance.get_d();
            let primes = private_instance.get_primes();
    
            private_instance = RSAPrivateKeyPair::new();
            private_instance.generate_from(&n, &d, &e, &primes);
            let signature = private_instance.sign_message(message);
            assert_ne!(signature, "".to_string())
        }
    }

    mod decrypt {
        use super::*;

        #[test]
        fn decrypt_message() {
            let message = "hello";
            let seed = "c993abb954f4ad796efa851ce4276f12250633ec4a8da1d1c8f37a82b633c1b7";
            let mut public_instance = public_keys::RSAPublicKeyPair::new();
            let mut private_instance = RSAPrivateKeyPair::new();
            private_instance.generate(1024, seed);
            public_instance.create(&private_instance.get_n(), &private_instance.get_e());
            let encrypted_message = public_instance.encrypt(message, seed);
            let decrypted_message = private_instance.decrypt(&encrypted_message);
            assert_eq!(decrypted_message, message);
        }
    
        #[test]
        #[should_panic]
        fn decrypt_message_with_invalid_message() {
            let seed = "c993abb954f4ad796efa851ce4276f12250633ec4a8da1d1c8f37a82b633c1b7";
            let mut private_instance = RSAPrivateKeyPair::new();
            private_instance.generate(1024, seed);
            private_instance.decrypt("");
        }
    
        #[test]
        #[should_panic]
        fn decrypt_message_without_keys() {
            let message = "hello";
            let seed = "c993abb954f4ad796efa851ce4276f12250633ec4a8da1d1c8f37a82b633c1b7";
            let mut public_instance = public_keys::RSAPublicKeyPair::new();
            let mut private_instance = RSAPrivateKeyPair::new();
            private_instance.generate(1024, seed);
            public_instance.create(&private_instance.get_n(), &private_instance.get_e());
            let encrypted_message = public_instance.encrypt(message, seed);
            private_instance = RSAPrivateKeyPair::new();
            private_instance.decrypt(&encrypted_message);
        }
    
        #[test]
        fn decrypt_message_with_generate_keys_from_data() {
            let message = "hello";
            let seed = "c993abb954f4ad796efa851ce4276f12250633ec4a8da1d1c8f37a82b633c1b7";
            let mut public_instance = public_keys::RSAPublicKeyPair::new();
            let mut private_instance = RSAPrivateKeyPair::new();
            private_instance.generate(1024, seed);
            let n = private_instance.get_n();
            let e = private_instance.get_e();
            let d = private_instance.get_d();
            let primes = private_instance.get_primes();
    
            public_instance.create(&n, &e);
            let encrypted_message = public_instance.encrypt(message, seed);
            private_instance = RSAPrivateKeyPair::new();
            private_instance.generate_from(&n, &d, &e, &primes);
            private_instance.decrypt(&encrypted_message);
        }
    }
}