extern crate rsa_lib;
use rsa_lib::{ RSAPrivateKeyPair, RSAPublicKeyPair };

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
