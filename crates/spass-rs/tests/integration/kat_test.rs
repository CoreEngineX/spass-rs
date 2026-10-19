//! Properties of the crypto dependencies that this crate's own round trips cannot see.
//!
//! The `tests/kat/*.plain` files are `openssl enc -d -aes-256-cbc` output for the committed
//! fixtures they are named after, keyed by Python's `hashlib.pbkdf2_hmac`.

use aes::Aes256;
use cbc::cipher::block_padding::NoPadding;
use cbc::cipher::{BlockModeDecrypt, KeyIvInit};
use cbc::Decryptor;
use hex::FromHex;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha256;
use spass::crypto::{CipherEngine, KeyDerivation};
use spass::domain::EntryPassword;
use spass::format::SpassDecoder;
use zeroize::ZeroizeOnDrop;

const FIXTURE_PASSWORD: &str = "TestPassword123";

fn decrypt_raw(file: &[u8]) -> Vec<u8> {
    let decoded = SpassDecoder::new()
        .decode_from_bytes(file)
        .expect("fixture decodes");
    let key = KeyDerivation::default()
        .derive_key(&EntryPassword::new(FIXTURE_PASSWORD.into()), decoded.salt())
        .expect("key derivation");
    CipherEngine::new()
        .decrypt(decoded.ciphertext(), &key, decoded.iv())
        .expect("fixture decrypts")
        .as_bytes()
        .to_vec()
}

#[test]
fn v30_fixture_decrypts_to_openssl_plaintext() {
    assert_eq!(
        decrypt_raw(include_bytes!(
            "../../../../gen-test/v30/test01-minimal.spass"
        )),
        include_bytes!("../kat/v30-test01-minimal.plain")
    );
}

#[test]
fn v31_fixture_decrypts_to_openssl_plaintext() {
    assert_eq!(
        decrypt_raw(include_bytes!(
            "../../../../gen-test/v31/test01-minimal.spass"
        )),
        include_bytes!("../kat/v31-test01-minimal.plain")
    );
}

#[test]
fn unknown_version_fixture_decrypts_to_openssl_plaintext() {
    assert_eq!(
        decrypt_raw(include_bytes!(
            "../../../../gen-test/besteffort/synthetic-v33.spass"
        )),
        include_bytes!("../kat/besteffort-synthetic-v33.plain")
    );
}

/// RFC 7914 section 11.
#[test]
fn pbkdf2_hmac_sha256_matches_rfc_7914() {
    let cases: [(&[u8], &[u8], u32, &str); 2] = [
        (
            b"passwd",
            b"salt",
            1,
            concat!(
                "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc",
                "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"
            ),
        ),
        (
            b"Password",
            b"NaCl",
            80_000,
            concat!(
                "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56",
                "a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"
            ),
        ),
    ];
    for (password, salt, rounds, expected) in cases {
        let mut derived = [0u8; 64];
        pbkdf2::<Hmac<Sha256>>(password, salt, rounds, &mut derived).expect("64-byte output");
        assert_eq!(hex::encode(derived), expected, "rounds = {rounds}");
    }
}

/// NIST SP 800-38A, F.2.6 CBC-AES256.Decrypt.
#[test]
fn aes_256_cbc_matches_sp_800_38a() {
    let key =
        <[u8; 32]>::from_hex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
            .expect("key hex");
    let iv = <[u8; 16]>::from_hex("000102030405060708090a0b0c0d0e0f").expect("iv hex");
    let mut buffer = hex::decode(concat!(
        "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d",
        "39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b"
    ))
    .expect("ciphertext hex");
    let plaintext = Decryptor::<Aes256>::new((&key).into(), (&iv).into())
        .decrypt_padded::<NoPadding>(&mut buffer)
        .expect("four whole blocks");
    assert_eq!(
        hex::encode(plaintext),
        concat!(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51",
            "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
        )
    );
}

#[cfg(target_arch = "aarch64")]
#[test]
fn aes_runs_on_the_armv8_instructions() {
    assert!(aes::hardware_accelerated());
}

#[test]
fn cipher_state_zeroizes_on_drop() {
    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<Aes256>();
    assert_zeroize_on_drop::<Decryptor<Aes256>>();
}
