//! Decryption pipeline for processing `SPass` files end-to-end.

#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;

use crate::crypto::{CipherEngine, CryptoValidator, KeyDerivation, PBKDF2_ITERATIONS};
use crate::domain::{EntryPassword, PasswordEntryCollection, SpassResult};
use crate::format::{
    CipherText, FormatValidator, InitializationVector, Salt, SpassDecoder, SpassFormatVersion,
};
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
    /// Build a pipeline with a custom PBKDF2 iteration count.
    /// Use [`PBKDF2_ITERATIONS`] (70,000) for production -- that's
    /// the value Samsung Pass actually uses, so anything else
    /// produces wrong keys. Lower counts only exist for tests
    /// where decryption speed matters more than fidelity.
    ///
    /// For the common case where you just want to decrypt a real
    /// `.spass` file, use [`DecryptionPipeline::default`] instead.
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

    /// Decrypts a `.spass` payload from a Base64 string. Use this
    /// when the bytes are already in memory (browser upload, network
    /// fetch, embedded fixture) instead of round-tripping through
    /// the filesystem.
    ///
    /// # Errors
    ///
    /// Same surface as [`Self::decrypt_file`] minus the filesystem
    /// errors:
    ///
    /// - `SpassError::Parsing` -- invalid Base64 or the decoded
    ///   payload is too short to carry the salt + IV header.
    /// - `SpassError::Validation` -- ciphertext is empty / not a
    ///   block multiple, or the decrypted bytes are missing the
    ///   `next_table` marker (typically a wrong-password failure
    ///   that bypassed PKCS7).
    /// - `SpassError::Decryption` -- wrong password (AES + PKCS7
    ///   rejected the padding).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use spass::pipeline::DecryptionPipeline;
    /// use spass::domain::EntryPassword;
    ///
    /// let pipeline = DecryptionPipeline::default();
    /// let base64_content = std::fs::read_to_string("export.spass").unwrap();
    /// let password = EntryPassword::new("password".to_string());
    /// let collection = pipeline.decrypt_string(&base64_content, &password).unwrap();
    /// ```
    pub fn decrypt_string(
        &self,
        content: &str,
        password: &EntryPassword,
    ) -> SpassResult<PasswordEntryCollection> {
        let decoded = self.decoder.decode_from_bytes(content.as_bytes())?;
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
        let version = SpassFormatVersion::detect(&decrypted)?;
        self.format_validator
            .validate_spass_marker(&decrypted, version)?;

        let format_id = match version {
            SpassFormatVersion::V30 => FormatId::SpassCsvV30,
            SpassFormatVersion::V31 => FormatId::SpassCsvV31,
        };

        self.parser_registry.parse(format_id, decrypted.as_bytes())
    }
}

impl Default for DecryptionPipeline {
    /// Pipeline preconfigured with [`PBKDF2_ITERATIONS`] (70,000) --
    /// the iteration count Samsung Pass actually uses. This is the
    /// constructor you want for decrypting real `.spass` files.
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
