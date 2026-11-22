//! The collection decoder: it decrypts into one plaintext copy and parses that into owned strings.
//! The buffer decoders are tested against it, and reproduce its trimming and error rules.

mod schema;
mod v30;

use std::num::NonZeroU32;

use aes::Aes256;
use cbc::Decryptor;
use cbc::cipher::{BlockModeDecrypt, KeyIvInit, block_padding::Pkcs7};

use crate::crypto::{CryptoValidator, KeyDerivation};
use crate::domain::{EntryPassword, SpassError, SpassResult, VersionStatus};
use crate::format::{
    DetectedVersion, FormatValidator, SpassDecoder, SpassFormatVersion, WireFamily,
};

pub use schema::parse_schema;
pub use v30::parse_v30;

/// One entry as the collection decoder produces it: url, username, password, name, note.
pub type OracleEntry = [String; 5];

/// Decrypts `file` into owned entries: the reference for `DecryptionPipeline::decrypt_to_buffer`.
///
/// # Errors
///
/// The errors the pipeline returns for the same file, except where only the buffer decoders
/// skip a check: they validate the header and the kept fields as UTF-8, not the whole plaintext.
pub fn decrypt(
    file: &[u8],
    password: &str,
    iterations: NonZeroU32,
) -> SpassResult<(Vec<OracleEntry>, VersionStatus)> {
    let decoded = SpassDecoder::new().decode_from_bytes(file)?;
    CryptoValidator::new().validate_ciphertext(decoded.ciphertext())?;
    let key = KeyDerivation::new(iterations)
        .derive_key(&EntryPassword::new(password.to_owned()), decoded.salt())?;

    let mut buffer = decoded.ciphertext().as_bytes().to_vec();
    let plaintext = Decryptor::<Aes256>::new(key.as_bytes().into(), decoded.iv().as_bytes().into())
        .decrypt_padded::<Pkcs7>(&mut buffer)
        .map(<[u8]>::to_vec)
        .map_err(|_| SpassError::Decryption("Decryption failed".to_string()))?;

    let validator = FormatValidator::new();
    validator.validate_data_size(&plaintext)?;
    match SpassFormatVersion::detect(&plaintext)? {
        DetectedVersion::Known(version) => {
            let entries = match version.wire_family() {
                WireFamily::V30Csv => {
                    validator.validate_v30_marker(&plaintext)?;
                    parse_v30(&plaintext)?
                }
                WireFamily::Schema35 => parse_schema(version.sentinel_str(), &plaintext)?.0,
            };
            Ok((entries, VersionStatus::Known { version }))
        }
        DetectedVersion::Unknown(sentinel) => {
            let (entries, report) = parse_schema(&sentinel, &plaintext)?;
            Ok((entries, VersionStatus::BestEffort { report }))
        }
    }
}

fn entry(
    url: String,
    username: String,
    password: String,
    name: String,
    note: String,
) -> OracleEntry {
    [
        trimmed(url),
        trimmed(username),
        password,
        trimmed(name),
        trimmed(note),
    ]
}

fn trimmed(text: String) -> String {
    let inner = text.trim();
    if inner.len() == text.len() {
        text
    } else {
        inner.to_owned()
    }
}
