use base64::{engine::general_purpose, Engine};
use std::ops::{Deref, RangeInclusive};
use std::path::Path;

use crate::domain::{Hex, SpassError, SpassResult};

/// The 20-byte salt extracted from a `.spass` file.
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct Salt<'d_file>(&'d_file [u8; 20]);

impl Salt<'_> {
    /// Returns the salt bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 20] {
        self.0
    }

    /// Returns the length in bytes (always 20).
    #[must_use]
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns the salt as a lowercase hex string.
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

/// The 16-byte initialization vector extracted from a `.spass` file.
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct InitializationVector<'d_file>(&'d_file [u8; 16]);

impl InitializationVector<'_> {
    /// Returns the IV bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0
    }

    /// Returns the IV as a lowercase hex string.
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

/// The encrypted payload extracted from a `.spass` file.
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct CipherText<'d_file>(&'d_file [u8]);

impl CipherText<'_> {
    /// Returns the ciphertext bytes.
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

    /// Returns the salt.
    ///
    /// # Panics
    ///
    /// Panics if the internal buffer violates the header invariant — this
    /// indicates a bug in `DecodedFile::new`, not a bad input file.
    #[must_use]
    pub fn salt(&self) -> Salt<'_> {
        let salt: &[u8; 20] = <&[u8; 20]>::try_from(&self.0[Self::SALT_RANGE])
            .expect("DecodedFile header invariant violated: salt must be 20 bytes");
        Salt(salt)
    }

    /// Returns the initialization vector.
    ///
    /// # Panics
    ///
    /// Panics if the internal buffer violates the header invariant — this
    /// indicates a bug in `DecodedFile::new`, not a bad input file.
    #[must_use]
    pub fn iv(&self) -> InitializationVector<'_> {
        let iv: &[u8; 16] = <&[u8; 16]>::try_from(&self.0[Self::IV_RANGE])
            .expect("DecodedFile header invariant violated: IV must be 16 bytes");
        InitializationVector(iv)
    }

    /// Returns the ciphertext (everything after the IV).
    #[must_use]
    pub fn ciphertext(&self) -> CipherText<'_> {
        CipherText(&self.0[Self::START_OF_CIPHER_RANGE..])
    }

    /// Constructs a `DecodedFile` from raw components. Only available in tests.
    #[cfg(test)]
    #[must_use]
    pub fn from_components(salt: &[u8; 20], iv: &[u8; 16], ciphertext: &[u8]) -> Self {
        let mut data = Vec::with_capacity(20 + 16 + ciphertext.len());
        data.extend_from_slice(salt);
        data.extend_from_slice(iv);
        data.extend_from_slice(ciphertext);
        DecodedFile(data.into_boxed_slice())
    }

    /// Returns a test builder with zero-filled defaults.
    #[cfg(test)]
    #[must_use]
    pub fn builder() -> DecodedFileBuilder {
        DecodedFileBuilder::new()
    }
}

/// Builder for `DecodedFile` in tests. Defaults all fields to zero bytes.
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

    /// Sets the salt.
    #[must_use]
    pub fn salt(mut self, salt: &[u8; 20]) -> Self {
        self.salt = *salt;
        self
    }

    /// Sets the IV.
    #[must_use]
    pub fn iv(mut self, iv: &[u8; 16]) -> Self {
        self.iv = *iv;
        self
    }

    /// Sets the ciphertext.
    #[must_use]
    pub fn ciphertext(mut self, ciphertext: &[u8]) -> Self {
        self.ciphertext = ciphertext.to_vec();
        self
    }

    /// Builds the `DecodedFile`.
    #[must_use]
    pub fn build(self) -> DecodedFile {
        let mut data = Vec::with_capacity(self.salt.len() + self.iv.len() + self.ciphertext.len());
        data.extend_from_slice(&self.salt);
        data.extend_from_slice(&self.iv);
        data.extend_from_slice(&self.ciphertext);
        DecodedFile(data.into_boxed_slice())
    }
}

/// Reads a `.spass` file and decodes its Base64 content into a [`DecodedFile`].
#[derive(Default)]
pub struct SpassDecoder;

impl SpassDecoder {
    /// Constructs a `SpassDecoder`.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Reads `path`, validates the `.spass` extension, and decodes the Base64 content.
    ///
    /// # Errors
    ///
    /// - `SpassError::Config` — wrong or missing file extension, or the file cannot be read.
    /// - `SpassError::Parsing` — invalid Base64 or decoded data is too short to contain the header.
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

        let file_content = std::fs::read_to_string(path)
            .map_err(|_| SpassError::Config("Could not open file".to_string()))?;

        self.decode_from_string(&file_content)
    }

    /// Decodes a Base64-encoded `.spass` payload.
    ///
    /// # Errors
    ///
    /// - `SpassError::Parsing` — invalid Base64 or decoded data too short.
    pub fn decode_from_string(&self, content: &str) -> SpassResult<DecodedFile> {
        let decoded = general_purpose::STANDARD
            .decode(content.trim())
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

        let result = decoder.decode_from_string(&encoded);
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

        let result = decoder.decode_from_string(&encoded);
        assert!(result.is_err());
    }
}
