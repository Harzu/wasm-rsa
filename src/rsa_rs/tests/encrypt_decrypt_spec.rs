extern crate rsa_lib;
use rsa_lib::{ RSAPrivateKeyPair, RSAPublicKeyPair };

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
