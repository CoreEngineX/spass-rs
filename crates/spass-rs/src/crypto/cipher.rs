use aes::Aes256;
use cbc::cipher::generic_array::GenericArray;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use cbc::Decryptor;
#[cfg(not(target_arch = "wasm32"))]
use std::time::Duration;

use super::key_derivation::DerivedKey;
use crate::domain::{DecryptedData, SpassError, SpassResult};
use crate::format::{CipherText, InitializationVector};

type Aes256CbcDec = Decryptor<Aes256>;

/// AES-256-CBC decryption engine.
///
/// On decryption failure the method sleeps for 100 µs before returning the
/// error. This makes the failure path constant-time from the caller's
/// perspective and prevents timing-based distinction between wrong password
/// and invalid padding.
#[derive(Default)]
pub struct CipherEngine;

impl CipherEngine {
    /// Constructs a `CipherEngine`.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Decrypts `ciphertext` with AES-256-CBC + PKCS7 padding.
    ///
    /// # Errors
    ///
    /// Returns `SpassError::Decryption` if the key is wrong, the ciphertext
    /// is corrupted, or padding is invalid.
    pub fn decrypt(
        &self,
        ciphertext: CipherText<'_>,
        key: &DerivedKey,
        iv: InitializationVector<'_>,
    ) -> SpassResult<DecryptedData> {
        let mut buffer = ciphertext.as_bytes().to_vec();

        let key_array = GenericArray::from_slice(key.as_bytes());
        let iv_array = GenericArray::from_slice(iv.as_bytes());

        let decryptor = Aes256CbcDec::new(key_array, iv_array);

        let result = decryptor.decrypt_padded_mut::<Pkcs7>(&mut buffer);

        if let Ok(plaintext) = result {
            Ok(DecryptedData::new(plaintext.to_vec()))
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
    use crate::format::DecodedFile;

    #[test]
    fn test_decrypt_with_wrong_key() {
        let cipher = CipherEngine::new();
        let kd = KeyDerivation::new(1000);

        let password = EntryPassword::new("wrong_password".into());
        let ciphertext_bytes = [0u8; 32];

        let decoded = DecodedFile::builder().ciphertext(&ciphertext_bytes).build();

        let key = kd.derive_key(&password, decoded.salt()).unwrap();
        let result = cipher.decrypt(decoded.ciphertext(), &key, decoded.iv());
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_with_correct_key() {
        use cbc::cipher::BlockEncryptMut;
        use cbc::Encryptor;

        let cipher = CipherEngine::new();
        let kd = KeyDerivation::new(1000);

        let password = EntryPassword::new("correct_password".into());
        let iv_bytes = [0u8; 16];
        let plaintext = b"Hello, this is a test message!!!";

        let mut buffer = plaintext.to_vec();
        buffer.resize(plaintext.len() + 16, 0);

        let decoded_for_key = DecodedFile::builder().build();
        let key = kd.derive_key(&password, decoded_for_key.salt()).unwrap();

        let key_array = GenericArray::from_slice(key.as_bytes());
        let iv_array = GenericArray::from_slice(&iv_bytes);

        let encryptor = Encryptor::<Aes256>::new(key_array, iv_array);
        let ciphertext_len = encryptor
            .encrypt_padded_mut::<Pkcs7>(&mut buffer, plaintext.len())
            .unwrap()
            .len();

        buffer.truncate(ciphertext_len);

        let decoded = DecodedFile::builder()
            .iv(&iv_bytes)
            .ciphertext(&buffer)
            .build();

        let result = cipher.decrypt(decoded.ciphertext(), &key, decoded.iv());

        assert!(result.is_ok());
        let decrypted = result.unwrap();
        assert_eq!(decrypted.as_bytes(), plaintext);
    }

    #[test]
    fn test_decrypt_constant_time_on_error() {
        use std::time::Instant;

        let cipher = CipherEngine::new();
        let kd = KeyDerivation::new(1000);

        let password = EntryPassword::new("test_password".into());
        let ciphertext_bytes = [0u8; 32];

        let decoded = DecodedFile::builder().ciphertext(&ciphertext_bytes).build();

        let key = kd.derive_key(&password, decoded.salt()).unwrap();

        let start = Instant::now();
        let _ = cipher.decrypt(decoded.ciphertext(), &key, decoded.iv());
        let elapsed = start.elapsed();

        assert!(elapsed.as_micros() >= 100);
    }
}
