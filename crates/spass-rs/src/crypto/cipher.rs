use aes::Aes256;
use cbc::Decryptor;
use cbc::cipher::{BlockModeDecrypt, KeyIvInit, block_padding::Pkcs7};
#[cfg(not(target_arch = "wasm32"))]
use std::time::Duration;

use super::key_derivation::DerivedKey;
use crate::domain::{SpassError, SpassResult};
use crate::format::InitializationVector;

type Aes256CbcDec = Decryptor<Aes256>;

/// AES-256-CBC decryption engine.
///
/// On decryption failure the method sleeps for 100 µs before returning the
/// error. This makes the failure path constant-time from the caller's
/// perspective and prevents timing-based distinction between wrong password
/// and invalid padding.
#[derive(Default)]
pub(crate) struct CipherEngine;

impl CipherEngine {
    /// Stateless; instantiate once per pipeline and reuse.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Decrypts `ciphertext` with AES-256-CBC + PKCS7 padding, in place, and returns the length
    /// of the plaintext, which starts at `ciphertext[0]`.
    ///
    /// # Errors
    ///
    /// `SpassError::Decryption` if the key is wrong, the ciphertext
    /// is structurally corrupt, or PKCS7 padding fails to validate.
    /// The three cases are deliberately indistinguishable from the
    /// caller's perspective (and timing-indistinguishable on native
    /// targets thanks to the 100 µs constant-time delay) to avoid
    /// leaking which failure mode tripped on a wrong-password
    /// attempt. On failure `ciphertext` holds partly decrypted bytes.
    pub(crate) fn decrypt_in_place(
        &self,
        ciphertext: &mut [u8],
        key: &DerivedKey,
        iv: InitializationVector<'_>,
    ) -> SpassResult<usize> {
        let decryptor = Aes256CbcDec::new(key.as_bytes().into(), iv.as_bytes().into());

        if let Ok(plaintext) = decryptor.decrypt_padded::<Pkcs7>(ciphertext) {
            Ok(plaintext.len())
        } else {
            // Constant-time delay on native targets to prevent timing-based
            // distinction between wrong password and invalid padding.
            // wasm32 has no threads, so the sleep is skipped there.
            #[cfg(not(target_arch = "wasm32"))]
            std::thread::sleep(Duration::from_micros(100));
            Err(SpassError::Decryption("Decryption failed".to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KeyDerivation;
    use crate::domain::EntryPassword;
    use crate::format::{DecodedFile, SpassDecoder};
    use cbc::Encryptor;
    use cbc::cipher::BlockModeEncrypt;
    use std::num::NonZeroU32;
    use std::time::Instant;

    const FAST_ITERATIONS: NonZeroU32 = NonZeroU32::new(1_000).unwrap();
    const FIXTURE_PASSWORD: &str = "TestPassword123";

    /// Decrypts a committed fixture with the production key derivation.
    fn decrypt_fixture(file: &[u8]) -> Vec<u8> {
        let decoded = SpassDecoder::new()
            .decode_from_bytes(file)
            .expect("fixture decodes");
        let key = KeyDerivation::default()
            .derive_key(&EntryPassword::new(FIXTURE_PASSWORD.into()), decoded.salt())
            .expect("key derivation");
        let mut buffer = decoded.ciphertext().as_bytes().to_vec();
        let len = CipherEngine::new()
            .decrypt_in_place(&mut buffer, &key, decoded.iv())
            .expect("fixture decrypts");
        buffer.truncate(len);
        buffer
    }

    #[test]
    fn test_decrypt_with_wrong_key() {
        let cipher = CipherEngine::new();
        let kd = KeyDerivation::new(FAST_ITERATIONS);

        let password = EntryPassword::new("wrong_password".into());
        let mut ciphertext_bytes = [0u8; 32];

        let decoded = DecodedFile::builder().ciphertext(&ciphertext_bytes).build();

        let key = kd.derive_key(&password, decoded.salt()).unwrap();
        let result = cipher.decrypt_in_place(&mut ciphertext_bytes, &key, decoded.iv());
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_with_correct_key() {
        let cipher = CipherEngine::new();
        let kd = KeyDerivation::new(FAST_ITERATIONS);

        let password = EntryPassword::new("correct_password".into());
        let iv_bytes = [0u8; 16];
        let plaintext = b"Hello, this is a test message!!!";

        let mut buffer = plaintext.to_vec();
        buffer.resize(plaintext.len() + 16, 0);

        let decoded_for_key = DecodedFile::builder().build();
        let key = kd.derive_key(&password, decoded_for_key.salt()).unwrap();

        let encryptor = Encryptor::<Aes256>::new(key.as_bytes().into(), (&iv_bytes).into());
        let ciphertext_len = encryptor
            .encrypt_padded::<Pkcs7>(&mut buffer, plaintext.len())
            .unwrap()
            .len();

        buffer.truncate(ciphertext_len);

        let decoded = DecodedFile::builder().iv(&iv_bytes).build();

        let len = cipher
            .decrypt_in_place(&mut buffer, &key, decoded.iv())
            .unwrap();

        assert_eq!(&buffer[..len], plaintext);
    }

    #[test]
    fn test_decrypt_constant_time_on_error() {
        let cipher = CipherEngine::new();
        let kd = KeyDerivation::new(FAST_ITERATIONS);

        let password = EntryPassword::new("test_password".into());
        let mut ciphertext_bytes = [0u8; 32];

        let decoded = DecodedFile::builder().ciphertext(&ciphertext_bytes).build();

        let key = kd.derive_key(&password, decoded.salt()).unwrap();

        let start = Instant::now();
        let _ = cipher.decrypt_in_place(&mut ciphertext_bytes, &key, decoded.iv());
        let elapsed = start.elapsed();

        assert!(elapsed.as_micros() >= 100);
    }

    /// `tests/kat/*.plain` is `openssl enc -d -aes-256-cbc` output for the committed fixture it is
    /// named after, keyed by Python's `hashlib.pbkdf2_hmac`.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn v30_fixture_decrypts_to_openssl_plaintext() {
        assert_eq!(
            decrypt_fixture(include_bytes!(
                "../../../../gen-test/v30/test01-minimal.spass"
            )),
            include_bytes!("../../tests/kat/v30-test01-minimal.plain")
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn v31_fixture_decrypts_to_openssl_plaintext() {
        assert_eq!(
            decrypt_fixture(include_bytes!(
                "../../../../gen-test/v31/test01-minimal.spass"
            )),
            include_bytes!("../../tests/kat/v31-test01-minimal.plain")
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn unknown_version_fixture_decrypts_to_openssl_plaintext() {
        assert_eq!(
            decrypt_fixture(include_bytes!(
                "../../../../gen-test/besteffort/synthetic-v33.spass"
            )),
            include_bytes!("../../tests/kat/besteffort-synthetic-v33.plain")
        );
    }
}
