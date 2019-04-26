extern crate rsa_lib;
use rsa_lib::{ RSAPrivateKeyPair, RSAPublicKeyPair };

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
