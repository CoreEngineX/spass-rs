//! Decryption pipeline for processing `SPass` files end-to-end.

use std::num::NonZeroU32;
#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;

use crate::crypto::{CipherEngine, CryptoValidator, KeyDerivation, PBKDF2_ITERATIONS};
use crate::domain::{DecryptOutcome, EntryPassword, SpassResult, VersionStatus};
use crate::entries::{Plaintext, decode_schema, decode_v30};
use crate::format::{
    DecodedBuffer, DetectedVersion, FormatValidator, SpassDecoder, SpassFormatVersion, WireFamily,
};

const UTF8_BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];

/// Full decryption pipeline for `.spass` files.
///
/// Steps:
/// 1. Skip a leading byte order mark and surrounding whitespace, and refuse a file too long to
///    decode to a payload within the 100 MiB ceiling
/// 2. Base64-decode the file into one zeroizing buffer
/// 3. Validate ciphertext (salt and IV are validated by their types)
/// 4. Derive AES-256 key via PBKDF2-HMAC-SHA256
/// 5. Decrypt with AES-256-CBC, in place
/// 6. Validate the decrypted size, then detect the version sentinel
/// 7. Dispatch by wire family: v30 to its dedicated decoder (after the
///    pinned marker check), everything else -- v31, v32, and unknown
///    sentinels -- to the default schema decoder
///
/// The pipeline returns a [`DecryptOutcome`] carrying every kept field in one
/// [`EntryBuffer`](crate::EntryBuffer) plus a [`VersionStatus`]. Consumers inspect the status to
/// render a "best-effort" banner when the file's version sentinel wasn't recognised.
///
/// # Examples
///
/// ```no_run
/// use spass::pipeline::DecryptionPipeline;
/// use spass::domain::{EntryPassword, VersionStatus};
///
/// let pipeline = DecryptionPipeline::new(spass::crypto::PBKDF2_ITERATIONS);
/// let password = EntryPassword::new("my_password".to_string());
/// let outcome = pipeline.decrypt_file("passwords.spass", &password)?;
///
/// match outcome.version_status {
///     VersionStatus::Known { .. } => println!("Decrypted {} entries", outcome.entries.len()),
///     VersionStatus::BestEffort { report } => {
///         eprintln!(
///             "warning: unknown .spass version \"{}\"; verify a few entries before importing",
///             report.sentinel
///         );
///     }
///     _ => {} // VersionStatus is #[non_exhaustive]
/// }
/// # Ok::<(), spass::SpassError>(())
/// ```
pub struct DecryptionPipeline {
    key_derivation: KeyDerivation,
    cipher: CipherEngine,
    crypto_validator: CryptoValidator,
    format_validator: FormatValidator,
    decoder: SpassDecoder,
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
    pub fn new(iterations: NonZeroU32) -> Self {
        Self {
            key_derivation: KeyDerivation::new(iterations),
            cipher: CipherEngine::new(),
            crypto_validator: CryptoValidator::new(),
            format_validator: FormatValidator::new(),
            decoder: SpassDecoder::new(),
        }
    }

    /// Decrypts the `.spass` file at `path`; its extension must be `.spass`. Not on wasm32.
    ///
    /// # Errors
    ///
    /// - `SpassError::Config` — wrong extension or unreadable file
    /// - Everything [`Self::decrypt_to_buffer`] returns
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use spass::pipeline::DecryptionPipeline;
    /// use spass::domain::EntryPassword;
    ///
    /// let pipeline = DecryptionPipeline::new(spass::crypto::PBKDF2_ITERATIONS);
    /// let password = EntryPassword::new("secret".to_string());
    /// let outcome = pipeline.decrypt_file("passwords.spass", &password).unwrap();
    /// println!("Decrypted {} passwords", outcome.entries.len());
    /// ```
    #[cfg(not(target_arch = "wasm32"))]
    pub fn decrypt_file<P: AsRef<Path>>(
        &self,
        path: P,
        password: &EntryPassword,
    ) -> SpassResult<DecryptOutcome> {
        let file = self.decoder.read_file(path)?;
        self.decrypt_to_buffer(&file, password)
    }

    /// Decrypts a `.spass` file's bytes, its Base64 text exactly as Samsung writes it, into one
    /// [`EntryBuffer`](crate::EntryBuffer). Use this when the bytes are already in memory
    /// (browser upload, network fetch, embedded fixture). One leading UTF-8 byte order mark and
    /// surrounding ASCII whitespace are skipped.
    ///
    /// # Errors
    ///
    /// - `SpassError::Validation` -- the file is longer than any export within the 100 MiB
    ///   plaintext ceiling (refused before Base64 and PBKDF2), the ciphertext is empty or not a
    ///   block multiple, the decrypted data is empty or over the ceiling, line 1 is empty or not
    ///   UTF-8, or a v30 file has no `next_table` on line 3.
    /// - `SpassError::Parsing` -- invalid Base64, a payload too short for the salt + IV header,
    ///   or malformed rows, quoting, headers or kept fields.
    /// - `SpassError::Decryption` -- wrong password (AES + PKCS7 rejected the padding).
    /// - `SpassError::UnknownVersionUnparseable` -- the line-1 sentinel is unrecognised or a
    ///   v31-family header lacks a required column; the contained report carries the diagnostic.
    pub fn decrypt_to_buffer(
        &self,
        file: &[u8],
        password: &EntryPassword,
    ) -> SpassResult<DecryptOutcome> {
        let text = file.strip_prefix(&UTF8_BOM).unwrap_or(file).trim_ascii();
        self.format_validator.validate_file_len(text.len())?;

        let mut decoded = self.decoder.decode_into_buffer(text)?;
        self.crypto_validator
            .validate_ciphertext(decoded.ciphertext())?;
        let key = self.key_derivation.derive_key(password, decoded.salt())?;
        let (iv, ciphertext) = decoded.iv_and_ciphertext_mut();
        let plaintext_len = self.cipher.decrypt_in_place(ciphertext, &key, iv)?;

        let plain = Plaintext::new(
            decoded.into_bytes(),
            DecodedBuffer::CIPHERTEXT_START,
            plaintext_len,
        );
        self.format_validator.validate_data_size(plain.as_slice())?;

        match SpassFormatVersion::detect(plain.as_slice())? {
            DetectedVersion::Known(version) => {
                let entries = match version.wire_family() {
                    WireFamily::V30Csv => {
                        self.format_validator
                            .validate_v30_marker(plain.as_slice())?;
                        decode_v30(plain)?
                    }
                    WireFamily::Schema35 => decode_schema(plain, version.sentinel_str())?.0,
                };
                Ok(DecryptOutcome {
                    entries,
                    version_status: VersionStatus::Known { version },
                })
            }
            DetectedVersion::Unknown(sentinel) => {
                let (entries, report) = decode_schema(plain, &sentinel)?;
                Ok(DecryptOutcome {
                    entries,
                    version_status: VersionStatus::BestEffort { report },
                })
            }
        }
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
    use crate::domain::SpassError;
    use crate::testkit::{SpassGenerator, TestEntry};
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use std::assert_matches;

    const FAST_ITERATIONS: NonZeroU32 = NonZeroU32::new(1_000).unwrap();
    const PASSWORD: &str = "pipeline-test";

    fn pipeline() -> DecryptionPipeline {
        DecryptionPipeline::new(FAST_ITERATIONS)
    }

    fn password() -> EntryPassword {
        EntryPassword::new(PASSWORD.to_string())
    }

    fn fixture() -> Vec<u8> {
        SpassGenerator::new(PASSWORD)
            .entry(TestEntry::new("https://a.example", "ann", "pw", "A", "n"))
            .generate_with_iterations(FAST_ITERATIONS)
            .into_bytes()
    }

    #[test]
    fn test_new_pipeline() {
        let _ = DecryptionPipeline::new(FAST_ITERATIONS);
    }

    #[test]
    fn test_default_pipeline() {
        let _ = DecryptionPipeline::default();
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_decrypt_with_invalid_salt() {
        let mut raw = vec![0u8; 36];
        raw.extend_from_slice(b"ciphertext123456");
        let file = STANDARD.encode(raw);

        let result = pipeline().decrypt_to_buffer(file.as_bytes(), &password());

        assert!(result.is_err());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_decrypt_with_empty_ciphertext() {
        let file = STANDARD.encode([0u8; 36]);

        let result = pipeline().decrypt_to_buffer(file.as_bytes(), &password());

        let err_msg = result.unwrap_err().to_string().to_lowercase();
        assert!(err_msg.contains("encrypted") || err_msg.contains("validation"));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn a_file_shorter_than_its_header_is_a_parsing_error() {
        let file = STANDARD.encode([0u8; 10]);

        let result = pipeline().decrypt_to_buffer(file.as_bytes(), &password());

        assert_matches!(result, Err(SpassError::Parsing(_)));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn a_leading_byte_order_mark_and_whitespace_are_skipped() {
        let plain = fixture();
        let mut file = UTF8_BOM.to_vec();
        file.extend_from_slice(&plain);
        file.extend_from_slice(b"\r\n");

        let outcome = pipeline().decrypt_to_buffer(&file, &password()).unwrap();

        assert_eq!(outcome.entries.len(), 1);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn a_file_over_the_length_bound_is_refused_without_decoding() {
        let file = vec![b'A'; crate::format::MAX_FILE_LEN + 1];

        let result = pipeline().decrypt_to_buffer(&file, &password());

        assert_matches!(result, Err(SpassError::Validation(_)));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn a_wrong_password_is_a_decryption_error() {
        let result =
            pipeline().decrypt_to_buffer(&fixture(), &EntryPassword::new("wrong".to_string()));

        assert_matches!(result, Err(SpassError::Decryption(_)));
    }
}
