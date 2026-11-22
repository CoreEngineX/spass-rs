//! Post-decryption structural checks for `.spass` payloads.
//!
//! Distinct from the crypto-level [`crate::crypto::validator`]:
//! that one validates *inputs* (password length, ciphertext block
//! alignment) before the AES call. This module validates *outputs*
//! after AES + PKCS7 succeed -- ensuring the decrypted bytes look
//! like a real Samsung Pass export and not a wrong-key collision.
//!
//! Three checks:
//! - v30's format marker is exactly `next_table` on line 3
//!   ([`FormatValidator::validate_v30_marker`]). The 35-column schema
//!   family needs no pinned check -- its decoder locates `next_table`
//!   itself and errors if it's absent.
//! - Payload size is non-empty and below a 100 MiB ceiling
//!   ([`FormatValidator::validate_data_size`]).
//! - The file's own length cannot decode to a larger payload
//!   ([`FormatValidator::validate_file_len`]), so an oversized file is
//!   refused before Base64 and PBKDF2.
//!
//! The marker check is the v30 wrong-password tripwire: AES-CBC with
//! PKCS7 occasionally produces valid-padding output for a wrong key,
//! but the resulting bytes won't carry the magic line.

use crate::domain::{SpassError, SpassResult};

/// 0-indexed line where v30 puts the `next_table` marker.
const V30_MARKER_LINE: usize = 2;

/// Largest decrypted payload accepted.
const MAX_DATA_SIZE: usize = 100 * 1024 * 1024;

/// Salt and IV, ahead of the ciphertext.
const FILE_HEADER_LEN: usize = 20 + 16;

/// PKCS#7 pads a payload of `n` bytes to the next block boundary, adding 1 to 16 bytes.
const MAX_PADDING_LEN: usize = 16;

/// Longest Base64 text that can decode to a payload within [`MAX_DATA_SIZE`].
pub(crate) const MAX_FILE_LEN: usize =
    (FILE_HEADER_LEN + MAX_DATA_SIZE + MAX_PADDING_LEN).div_ceil(3) * 4;

/// Structural checks on decrypted `.spass` data. See module docs for
/// the role this plays in distinguishing wrong-password output from
/// real exports.
#[derive(Default)]
pub struct FormatValidator;

impl FormatValidator {
    /// Stateless; instantiate once per pipeline and reuse.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Checks that v30's marker line (line 3, index 2) is exactly
    /// `next_table`. Called by the pipeline only for the v30 wire
    /// family, after the sentinel detector reads line 1.
    ///
    /// # Errors
    ///
    /// `SpassError::Validation` if the data has fewer lines than
    /// required, a line can't be read, or the marker line doesn't
    /// equal `next_table`.
    pub fn validate_v30_marker(&self, data: &[u8]) -> SpassResult<()> {
        let Some(line) = data
            .split_inclusive(|&byte| byte == b'\n')
            .nth(V30_MARKER_LINE)
        else {
            return Err(SpassError::Validation(
                "Insufficient data lines to validate marker".to_string(),
            ));
        };

        let line = line
            .strip_suffix(b"\n")
            .map_or(line, |line| line.strip_suffix(b"\r").unwrap_or(line));
        let line = std::str::from_utf8(line)
            .map_err(|_| {
                SpassError::Validation(
                    "Failed to read line: stream did not contain valid UTF-8".to_string(),
                )
            })?
            .trim();

        if line == "next_table" {
            return Ok(());
        }
        Err(SpassError::Validation(format!(
            "Expected 'next_table' on line {}, found '{line}'",
            V30_MARKER_LINE + 1,
        )))
    }

    /// Checks that the decrypted data is non-empty and does not
    /// exceed 100 MiB. The ceiling is a defense against
    /// pathological inputs that would otherwise cause the decoder to
    /// allocate unboundedly -- not a real-world Samsung Pass export
    /// size limit (those are typically under 5 MB).
    ///
    /// # Errors
    ///
    /// `SpassError::Validation` if the data is empty or exceeds 100 MiB.
    pub fn validate_data_size(&self, data: &[u8]) -> SpassResult<()> {
        if data.is_empty() {
            return Err(SpassError::Validation("Data cannot be empty".to_string()));
        }

        if data.len() > MAX_DATA_SIZE {
            return Err(too_large());
        }

        Ok(())
    }

    /// Checks that a `.spass` file's Base64 text, `len` bytes long, can decode to a payload
    /// within the 100 MiB ceiling. Never refuses a file whose payload fits.
    ///
    /// # Errors
    ///
    /// `SpassError::Validation` if `len` exceeds the longest text a conforming payload encodes to.
    pub fn validate_file_len(&self, len: usize) -> SpassResult<()> {
        if len > MAX_FILE_LEN {
            return Err(too_large());
        }
        Ok(())
    }
}

fn too_large() -> SpassError {
    SpassError::Validation("Data size exceeds maximum allowed size".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(s: &str) -> &[u8] {
        s.as_bytes()
    }

    #[test]
    fn validate_v30_marker_on_line_3() {
        let v = FormatValidator::new();
        let d = data("spass_export_v1\nfoo\nnext_table\nrest\n");
        v.validate_v30_marker(d).unwrap();
    }

    #[test]
    fn v30_marker_elsewhere_errors() {
        let v = FormatValidator::new();
        let d = data("spass_export_v1\nfoo\nbar\nnext_table\n");
        let err = v.validate_v30_marker(d).unwrap_err();
        assert!(err.to_string().contains("line 3"));
    }

    #[test]
    fn v30_marker_missing_lines_errors() {
        let v = FormatValidator::new();
        let d = data("spass_export_v1\nfoo\n");
        let err = v.validate_v30_marker(d).unwrap_err();
        assert!(err.to_string().contains("Insufficient"));
    }

    #[test]
    fn validate_data_size_rejects_empty() {
        let v = FormatValidator::new();
        let d = data("");
        assert!(v.validate_data_size(d).is_err());
    }

    #[test]
    fn validate_data_size_rejects_over_the_ceiling() {
        let v = FormatValidator::new();
        let at_ceiling = vec![0u8; MAX_DATA_SIZE];
        assert!(v.validate_data_size(&at_ceiling).is_ok());
        let over = vec![0u8; MAX_DATA_SIZE + 1];
        assert!(v.validate_data_size(&over).is_err());
    }

    #[test]
    fn file_len_bound_is_the_text_of_the_largest_payload() {
        // The largest payload, already block-aligned, gains a whole block of padding.
        let ciphertext = (MAX_DATA_SIZE / 16 + 1) * 16;
        assert_eq!(
            base64::encoded_len(FILE_HEADER_LEN + ciphertext, true),
            Some(MAX_FILE_LEN)
        );

        let v = FormatValidator::new();
        assert!(v.validate_file_len(MAX_FILE_LEN).is_ok());
        assert!(v.validate_file_len(MAX_FILE_LEN + 1).is_err());
    }
}
