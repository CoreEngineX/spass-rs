use crate::{
    domain::{SpassError, SpassResult},
    format::CipherText,
};

/// Validates inputs to cryptographic operations.
///
/// Salt and IV are not validated here — their types (`Salt` and
/// `InitializationVector`) enforce correct lengths as type invariants.
#[derive(Default)]
pub struct CryptoValidator;

impl CryptoValidator {
    /// Constructs a `CryptoValidator`.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Returns an error if `password` is empty.
    ///
    /// # Errors
    ///
    /// Returns `SpassError::Validation` if the password is empty.
    pub fn validate_password(&self, password: &[u8]) -> SpassResult<()> {
        if password.is_empty() {
            return Err(SpassError::Validation(
                "Password cannot be empty".to_string(),
            ));
        }
        Ok(())
    }

    /// Returns an error if `ciphertext` is empty or not a multiple of the AES block size (16 bytes).
    ///
    /// # Errors
    ///
    /// Returns `SpassError::Validation` on failure.
    pub fn validate_ciphertext(&self, ciphertext: CipherText<'_>) -> SpassResult<()> {
        if ciphertext.as_bytes().is_empty() {
            return Err(SpassError::Validation(
                "Encrypted data cannot be empty".to_string(),
            ));
        }

        if ciphertext.as_bytes().len() % 16 != 0 {
            return Err(SpassError::Validation(
                "Encrypted data size must be multiple of 16 bytes".to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::DecodedFile;

    #[test]
    fn test_validate_ciphertext() {
        let validator = CryptoValidator::new();

        // Empty ciphertext
        let decoded_empty = DecodedFile::builder().build();
        assert!(validator
            .validate_ciphertext(decoded_empty.ciphertext())
            .is_err());

        // Invalid length (not multiple of 16)
        let invalid_ciphertext = [0u8; 15];
        let decoded_invalid = DecodedFile::builder()
            .ciphertext(&invalid_ciphertext)
            .build();
        assert!(validator
            .validate_ciphertext(decoded_invalid.ciphertext())
            .is_err());

        // Valid 16 bytes
        let valid_ciphertext = [0u8; 16];
        let decoded_valid = DecodedFile::builder().ciphertext(&valid_ciphertext).build();
        assert!(validator
            .validate_ciphertext(decoded_valid.ciphertext())
            .is_ok());

        // Valid 32 bytes
        let valid_ciphertext_32 = [0u8; 32];
        let decoded_valid_32 = DecodedFile::builder()
            .ciphertext(&valid_ciphertext_32)
            .build();
        assert!(validator
            .validate_ciphertext(decoded_valid_32.ciphertext())
            .is_ok());
    }
}
