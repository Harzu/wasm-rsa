use sha2::{ Sha256 };
use wasm_bindgen::prelude::*;

use rand::prelude::*;
use rand::{ SeedableRng };

use rsa::hash::Hash;
use rsa::padding::PaddingScheme;
use rsa::{ RSAPrivateKey, RSAPublicKey, PublicKeyParts };

use num_bigint_dig::{ BigUint };

mod utils;
pub mod public_keys;
pub mod private_keys;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

#[cfg(test)]
mod test {
    use super::*;
    use public_keys::RSAPublicKeyPair;
    use private_keys::RSAPrivateKeyPair;

    #[test]
    fn encrypt_message() {
        let message = "hello";
        let seed = "c993abb954f4ad796efa851ce4276f12250633ec4a8da1d1c8f37a82b633c1b7";
        let mut public_instance = RSAPublicKeyPair::new();
        let mut private_instance = RSAPrivateKeyPair::new();
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
        let mut private_instance = RSAPrivateKeyPair::new();
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
        let mut private_instance = RSAPrivateKeyPair::new();
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

    #[test]
    fn decrypt_message() {
        let message = "hello";
        let seed = "c993abb954f4ad796efa851ce4276f12250633ec4a8da1d1c8f37a82b633c1b7";
        let mut public_instance = RSAPublicKeyPair::new();
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
        let mut public_instance = RSAPublicKeyPair::new();
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
        let mut public_instance = RSAPublicKeyPair::new();
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

    #[test]
    fn create_keys() {
        let seed = "c993abb954f4ad796efa851ce4276f12250633ec4a8da1d1c8f37a82b633c1b7";
        let mut public_instance = RSAPublicKeyPair::new();
        let mut private_instance = RSAPrivateKeyPair::new();
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
        let mut private_instance = RSAPrivateKeyPair::new();
        private_instance.generate(1024, seed);
        public_instance.create("", &private_instance.get_e());
    }

    #[test]
    #[should_panic]
    fn create_keys_without_e() {
        let seed = "c993abb954f4ad796efa851ce4276f12250633ec4a8da1d1c8f37a82b633c1b7";
        let mut public_instance = RSAPublicKeyPair::new();
        let mut private_instance = RSAPrivateKeyPair::new();
        private_instance.generate(1024, seed);
        public_instance.create(&private_instance.get_n(), "");
    }

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

    #[test]
    fn verify_message() {
        let message = "c993abb954f4ad796efa851ce4276f12250633ec4a8da1d1c8f37a82b633c1b7";
        let seed = "c993abb954f4ad796efa851ce4276f12250633ec4a8da1d1c8f37a82b633c1b7";
        let mut public_instance = RSAPublicKeyPair::new();
        let mut private_instance = RSAPrivateKeyPair::new();
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
        let mut private_instance = RSAPrivateKeyPair::new();
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
        let mut private_instance = RSAPrivateKeyPair::new();
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
        let mut private_instance = RSAPrivateKeyPair::new();
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
        let mut private_instance = RSAPrivateKeyPair::new();
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
        let mut private_instance = RSAPrivateKeyPair::new();
        private_instance.generate(1024, seed);
        let signature = private_instance.sign_message(message);
        public_instance.verify_message(message, &signature);
    }
}
