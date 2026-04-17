//! Decryption pipeline for processing `SPass` files end-to-end.

#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;

use crate::crypto::{CipherEngine, CryptoValidator, KeyDerivation, PBKDF2_ITERATIONS};
use crate::domain::{EntryPassword, PasswordEntryCollection, SpassResult};
use crate::format::{CipherText, FormatValidator, InitializationVector, Salt, SpassDecoder};
use crate::parser::{FormatId, ParserRegistry};

/// Full decryption pipeline for `.spass` files.
///
/// Steps:
/// 1. Base64-decode the file
/// 2. Validate ciphertext (salt and IV are validated by their types)
/// 3. Derive AES-256 key via PBKDF2-HMAC-SHA256
/// 4. Decrypt with AES-256-CBC
/// 5. Validate the decrypted format (`next_table` marker, size)
/// 6. Parse the internal CSV into password entries
///
/// # Examples
///
/// ```no_run
/// use spass::pipeline::DecryptionPipeline;
/// use spass::domain::EntryPassword;
///
/// let pipeline = DecryptionPipeline::new(spass::crypto::PBKDF2_ITERATIONS);
/// let password = EntryPassword::new("my_password".to_string());
/// let result = pipeline.decrypt_file("passwords.spass", &password);
///
/// match result {
///     Ok(collection) => println!("Decrypted {} entries", collection.len()),
///     Err(e) => eprintln!("Decryption failed: {}", e),
/// }
/// ```
pub struct DecryptionPipeline {
    key_derivation: KeyDerivation,
    cipher: CipherEngine,
    crypto_validator: CryptoValidator,
    format_validator: FormatValidator,
    decoder: SpassDecoder,
    parser_registry: ParserRegistry,
}

impl DecryptionPipeline {
    /// Constructs a pipeline with `iterations` PBKDF2 rounds.
    ///
    /// Use 70,000 or higher for production. Lower values are only appropriate
    /// for tests where speed matters more than brute-force resistance.
    ///
    /// # Examples
    ///
    /// ```
    /// use spass::pipeline::DecryptionPipeline;
    ///
    /// let pipeline = DecryptionPipeline::new(spass::crypto::PBKDF2_ITERATIONS);
    /// ```
    #[must_use]
    pub fn new(iterations: u32) -> Self {
        Self {
            key_derivation: KeyDerivation::new(iterations),
            cipher: CipherEngine::new(),
            crypto_validator: CryptoValidator::new(),
            format_validator: FormatValidator::new(),
            decoder: SpassDecoder::new(),
            parser_registry: ParserRegistry::new(),
        }
    }

    /// Decrypts a `.spass` file at `path`.
    ///
    /// # Errors
    ///
    /// - `SpassError::Config` — wrong extension or unreadable file
    /// - `SpassError::Parsing` — invalid Base64 or file structure
    /// - `SpassError::Validation` — bad crypto parameters or format marker missing
    /// - `SpassError::Decryption` — wrong password or corrupted data
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use spass::pipeline::DecryptionPipeline;
    /// use spass::domain::EntryPassword;
    ///
    /// let pipeline = DecryptionPipeline::new(spass::crypto::PBKDF2_ITERATIONS);
    /// let password = EntryPassword::new("secret".to_string());
    /// let collection = pipeline.decrypt_file("passwords.spass", &password).unwrap();
    /// println!("Decrypted {} passwords", collection.len());
    /// ```
    #[cfg(not(target_arch = "wasm32"))]
    pub fn decrypt_file<P: AsRef<Path>>(
        &self,
        path: P,
        password: &EntryPassword,
    ) -> SpassResult<PasswordEntryCollection> {
        let decoded = self.decoder.decode_from_file(path)?;
        self.decrypt_data(decoded.ciphertext(), password, decoded.salt(), decoded.iv())
    }

    /// Decrypts a `.spass` file from its text content.
    ///
    /// # Errors
    ///
    /// Returns `SpassError` if any pipeline step fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use spass::pipeline::DecryptionPipeline;
    /// use spass::domain::EntryPassword;
    ///
    /// let pipeline = DecryptionPipeline::new(spass::crypto::PBKDF2_ITERATIONS);
    /// let base64_content = "...";
    /// let password = EntryPassword::new("password".to_string());
    /// let collection = pipeline.decrypt_string(base64_content, &password).unwrap();
    /// ```
    pub fn decrypt_string(
        &self,
        content: &str,
        password: &EntryPassword,
    ) -> SpassResult<PasswordEntryCollection> {
        let decoded = self.decoder.decode_from_string(content)?;
        self.decrypt_data(decoded.ciphertext(), password, decoded.salt(), decoded.iv())
    }

    fn decrypt_data(
        &self,
        ciphertext: CipherText<'_>,
        password: &EntryPassword,
        salt: Salt<'_>,
        iv: InitializationVector<'_>,
    ) -> SpassResult<PasswordEntryCollection> {
        self.crypto_validator.validate_ciphertext(ciphertext)?;

        let key = self.key_derivation.derive_key(password, salt)?;
        let decrypted = self.cipher.decrypt(ciphertext, &key, iv)?;

        self.format_validator.validate_data_size(&decrypted)?;
        self.format_validator.validate_spass_marker(&decrypted)?;

        let format_id = self
            .parser_registry
            .auto_detect(decrypted.as_bytes())
            .unwrap_or(FormatId::SpassCsv);

        self.parser_registry.parse(format_id, decrypted.as_bytes())
    }
}

impl Default for DecryptionPipeline {
    /// Constructs a pipeline with 70,000 PBKDF2 iterations.
    ///
    /// # Examples
    ///
    /// ```
    /// use spass::pipeline::DecryptionPipeline;
    ///
    /// let pipeline = DecryptionPipeline::default();
    /// ```
    fn default() -> Self {
        Self::new(PBKDF2_ITERATIONS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_pipeline() {
        let _ = DecryptionPipeline::new(1000);
    }

    #[test]
    fn test_default_pipeline() {
        let _ = DecryptionPipeline::default();
    }

    #[test]
    fn test_decrypt_data_with_invalid_salt() {
        use crate::format::DecodedFile;

        let pipeline = DecryptionPipeline::new(1000);
        let ciphertext_bytes = b"ciphertext123456";

        let decoded = DecodedFile::builder().ciphertext(ciphertext_bytes).build();

        let result = pipeline.decrypt_data(
            decoded.ciphertext(),
            &EntryPassword::new("password".into()),
            decoded.salt(),
            decoded.iv(),
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_data_with_empty_ciphertext() {
        use crate::format::DecodedFile;

        let pipeline = DecryptionPipeline::new(1000);
        let decoded = DecodedFile::builder().build();

        let result = pipeline.decrypt_data(
            decoded.ciphertext(),
            &EntryPassword::new("password".into()),
            decoded.salt(),
            decoded.iv(),
        );

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string().to_lowercase();
        assert!(err_msg.contains("encrypted") || err_msg.contains("validation"));
    }
}
