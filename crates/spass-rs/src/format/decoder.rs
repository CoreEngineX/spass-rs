//! Binary layout of a Base64-decoded `.spass` file.
//!
//! A `.spass` file is a single Base64 blob whose decoded bytes follow
//! a fixed three-part header:
//!
//! | Bytes      | Meaning                                  |
//! |------------|------------------------------------------|
//! | `0..20`    | PBKDF2 salt (20 bytes, opaque)           |
//! | `20..36`   | AES-CBC initialization vector (16 bytes) |
//! | `36..`     | AES-256-CBC ciphertext (PKCS7-padded)    |
//!
//! Newtypes [`Salt`], [`InitializationVector`], and [`CipherText`]
//! borrow from a [`DecodedFile`] so the three regions can be passed
//! to the crypto layer without copying. The whole header is
//! validated by [`DecodedFile::new`] (private) -- once you hold a
//! `DecodedFile` the accessors can't panic on the contents, only on
//! the buffer length, which `new` already enforced.

use base64::{engine::general_purpose, Engine};
use std::ops::{Deref, RangeInclusive};
use std::path::Path;

use crate::domain::{Hex, SpassError, SpassResult};

/// 20-byte PBKDF2 salt extracted from the `.spass` header.
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct Salt<'d_file>(&'d_file [u8; 20]);

impl Salt<'_> {
    /// Borrow the raw 20 bytes for passing to PBKDF2.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 20] {
        self.0
    }

    /// Always 20. Exposed so callers can `Deref::deref().len()`-style
    /// without remembering the const.
    #[must_use]
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Lowercase hex encoding; useful for debug logging.
    #[must_use]
    pub fn to_hex(&self) -> Hex {
        Hex::encode(self.0)
    }
}

impl Deref for Salt<'_> {
    type Target = [u8; 20];

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

/// 16-byte AES-CBC initialization vector extracted from the
/// `.spass` header.
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct InitializationVector<'d_file>(&'d_file [u8; 16]);

impl InitializationVector<'_> {
    /// Borrow the raw 16 bytes for passing to the AES-CBC engine.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0
    }

    /// Lowercase hex encoding; useful for debug logging.
    #[must_use]
    pub fn to_hex(&self) -> Hex {
        Hex::encode(self.0)
    }
}

impl Deref for InitializationVector<'_> {
    type Target = [u8; 16];

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

/// AES-256-CBC ciphertext (PKCS7-padded) -- everything in the
/// `.spass` payload after the 36-byte salt + IV prefix.
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct CipherText<'d_file>(&'d_file [u8]);

impl CipherText<'_> {
    /// Borrow the raw encrypted payload for AES-CBC decryption.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0
    }
}

impl Deref for CipherText<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

/// A `.spass` file after Base64 decoding.
///
/// Layout: `[0..20)` = salt, `[20..36)` = IV, `[36..)` = ciphertext.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DecodedFile(Box<[u8]>);

impl DecodedFile {
    const SALT_RANGE: RangeInclusive<usize> = 0..=19;
    const IV_RANGE: RangeInclusive<usize> = 20..=35;
    const START_OF_CIPHER_RANGE: usize = 36;

    fn new(data: Vec<u8>) -> SpassResult<Self> {
        if data.len() < Self::START_OF_CIPHER_RANGE {
            return Err(SpassError::Parsing("Incomplete file header".to_string()));
        }
        Ok(DecodedFile(data.into_boxed_slice()))
    }

    /// # Panics
    ///
    /// Only if the internal buffer somehow has fewer than 20 bytes,
    /// which `DecodedFile::new` already rejected. A panic here would
    /// indicate a bug in `new`, not a malformed input file.
    #[must_use]
    pub fn salt(&self) -> Salt<'_> {
        let salt: &[u8; 20] = <&[u8; 20]>::try_from(&self.0[Self::SALT_RANGE])
            .expect("DecodedFile header invariant violated: salt must be 20 bytes");
        Salt(salt)
    }

    /// # Panics
    ///
    /// Only if the internal buffer somehow has fewer than 36 bytes,
    /// which `DecodedFile::new` already rejected. A panic here would
    /// indicate a bug in `new`, not a malformed input file.
    #[must_use]
    pub fn iv(&self) -> InitializationVector<'_> {
        let iv: &[u8; 16] = <&[u8; 16]>::try_from(&self.0[Self::IV_RANGE])
            .expect("DecodedFile header invariant violated: IV must be 16 bytes");
        InitializationVector(iv)
    }

    /// Encrypted payload region (everything after the 36-byte
    /// salt + IV header).
    #[must_use]
    pub fn ciphertext(&self) -> CipherText<'_> {
        CipherText(&self.0[Self::START_OF_CIPHER_RANGE..])
    }

    /// Test-only constructor that bypasses the Base64 decode step
    /// and lets a test build a `DecodedFile` from the three regions
    /// directly. Not exposed in release builds.
    #[cfg(test)]
    #[must_use]
    pub fn from_components(salt: &[u8; 20], iv: &[u8; 16], ciphertext: &[u8]) -> Self {
        let mut data = Vec::with_capacity(20 + 16 + ciphertext.len());
        data.extend_from_slice(salt);
        data.extend_from_slice(iv);
        data.extend_from_slice(ciphertext);
        DecodedFile(data.into_boxed_slice())
    }

    /// Test-only entry to [`DecodedFileBuilder`] (defaults to
    /// zero-filled salt + IV + empty ciphertext). Used by the
    /// crypto + format test suites to build fake inputs without
    /// touching disk or the Base64 codec.
    #[cfg(test)]
    #[must_use]
    pub fn builder() -> DecodedFileBuilder {
        DecodedFileBuilder::new()
    }
}

/// Test-only builder for [`DecodedFile`]. Defaults all three regions
/// to zeroed bytes; override any of them with `.salt(...)`,
/// `.iv(...)`, `.ciphertext(...)` before `.build()`.
#[cfg(test)]
pub struct DecodedFileBuilder {
    salt: [u8; 20],
    iv: [u8; 16],
    ciphertext: Vec<u8>,
}

#[cfg(test)]
impl DecodedFileBuilder {
    fn new() -> Self {
        Self {
            salt: [0u8; 20],
            iv: [0u8; 16],
            ciphertext: Vec::new(),
        }
    }

    /// Override the default zero-filled salt.
    #[must_use]
    pub fn salt(mut self, salt: &[u8; 20]) -> Self {
        self.salt = *salt;
        self
    }

    /// Override the default zero-filled IV.
    #[must_use]
    pub fn iv(mut self, iv: &[u8; 16]) -> Self {
        self.iv = *iv;
        self
    }

    /// Override the default empty ciphertext.
    #[must_use]
    pub fn ciphertext(mut self, ciphertext: &[u8]) -> Self {
        self.ciphertext = ciphertext.to_vec();
        self
    }

    /// Concatenate the three regions into a [`DecodedFile`] without
    /// running the Base64 step.
    #[must_use]
    pub fn build(self) -> DecodedFile {
        let mut data = Vec::with_capacity(self.salt.len() + self.iv.len() + self.ciphertext.len());
        data.extend_from_slice(&self.salt);
        data.extend_from_slice(&self.iv);
        data.extend_from_slice(&self.ciphertext);
        DecodedFile(data.into_boxed_slice())
    }
}

/// Reads a `.spass` file from disk (or string) and produces a
/// [`DecodedFile`]. The decoder validates the extension and runs the
/// Base64 step; it does NOT decrypt -- pass the result through the
/// pipeline for that.
#[derive(Default)]
pub struct SpassDecoder;

impl SpassDecoder {
    /// Stateless; instantiate once per pipeline and reuse.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Reads `path`, validates the `.spass` extension, and decodes
    /// the Base64 content.
    ///
    /// # Errors
    ///
    /// - `SpassError::Config` -- wrong or missing file extension, or
    ///   the file can't be opened.
    /// - `SpassError::Parsing` -- invalid Base64 or the decoded
    ///   payload is shorter than the 36-byte salt + IV header.
    pub fn decode_from_file<P: AsRef<Path>>(&self, path: P) -> SpassResult<DecodedFile> {
        match path.as_ref().extension() {
            Some(ext) if ext != "spass" => {
                return Err(SpassError::Config(
                    "Expected .spass file extension".to_string(),
                ))
            }
            None => return Err(SpassError::Config("File has no extension".to_string())),
            Some(_) => {}
        }

        let file_bytes = std::fs::read(path)
            .map_err(|_| SpassError::Config("Could not open file".to_string()))?;

        self.decode_from_bytes(&file_bytes)
    }

    /// Decodes a Base64-encoded `.spass` payload from raw bytes. Use
    /// this when the input is already in memory (browser uploads,
    /// network reads, embedded fixtures). Reading raw bytes also
    /// skips the UTF-8 validation that `read_to_string` would do --
    /// pointless work since Base64's alphabet is pure ASCII.
    ///
    /// Callers holding a `&str` can pass `s.as_bytes()` -- zero-cost
    /// since `&str` is already UTF-8 bytes.
    ///
    /// # Errors
    ///
    /// - `SpassError::Parsing` -- invalid Base64 or the decoded
    ///   payload is shorter than the 36-byte salt + IV header.
    pub fn decode_from_bytes(&self, content: &[u8]) -> SpassResult<DecodedFile> {
        let decoded = general_purpose::STANDARD
            .decode(content.trim_ascii())
            .map_err(|_| SpassError::Parsing("Base64 decode error".to_string()))?;

        DecodedFile::new(decoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_valid_base64() {
        let decoder = SpassDecoder::new();
        let data = [0u8; 100];
        let encoded = general_purpose::STANDARD.encode(data);

        let result = decoder.decode_from_bytes(encoded.as_bytes());
        assert!(result.is_ok());

        let file = result.unwrap();
        assert_eq!(file.salt().len(), 20);
        assert_eq!(file.iv().len(), 16);
    }

    #[test]
    fn test_decode_too_short() {
        let decoder = SpassDecoder::new();
        let data = [0u8; 10];
        let encoded = general_purpose::STANDARD.encode(data);

        let result = decoder.decode_from_bytes(encoded.as_bytes());
        assert!(result.is_err());
    }
}
