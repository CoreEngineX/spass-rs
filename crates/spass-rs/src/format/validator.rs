//! Post-decryption structural checks for `.spass` payloads.
//!
//! Distinct from the crypto-level [`crate::crypto::validator`]:
//! that one validates *inputs* (password length, ciphertext block
//! alignment) before the AES call. This module validates *outputs*
//! after AES + PKCS7 succeed -- ensuring the decrypted bytes look
//! like a real Samsung Pass export and not a wrong-key collision.
//!
//! Two checks:
//! - v30's format marker is exactly `next_table` on line 3
//!   ([`FormatValidator::validate_v30_marker`]). The 35-column schema
//!   family needs no pinned check -- its parser locates `next_table`
//!   itself and errors if it's absent.
//! - Payload size is non-empty and below a 100 MB ceiling
//!   ([`FormatValidator::validate_data_size`]).
//!
//! The marker check is the v30 wrong-password tripwire: AES-CBC with
//! PKCS7 occasionally produces valid-padding output for a wrong key,
//! but the resulting bytes won't carry the magic line.

use crate::domain::{DecryptedData, SpassError, SpassResult};
use std::io::{BufRead, BufReader, Cursor};

/// 0-indexed line where v30 puts the `next_table` marker.
const V30_MARKER_LINE: usize = 2;

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
    pub fn validate_v30_marker(&self, data: &DecryptedData) -> SpassResult<()> {
        let cursor = Cursor::new(data.as_bytes());
        let reader = BufReader::new(cursor);

        for (line_num, line_result) in reader.lines().enumerate() {
            if line_num == V30_MARKER_LINE {
                let line_content = line_result
                    .map_err(|e| SpassError::Validation(format!("Failed to read line: {e}")))?;

                if line_content.trim() == "next_table" {
                    return Ok(());
                }
                return Err(SpassError::Validation(format!(
                    "Expected 'next_table' on line {}, found '{}'",
                    V30_MARKER_LINE + 1,
                    line_content.trim()
                )));
            }
        }

        Err(SpassError::Validation(
            "Insufficient data lines to validate marker".to_string(),
        ))
    }

    /// Checks that the decrypted data is non-empty and does not
    /// exceed 100 MB. The 100 MB ceiling is a defense against
    /// pathological inputs that would otherwise cause the parser to
    /// allocate unboundedly -- not a real-world Samsung Pass export
    /// size limit (those are typically under 5 MB).
    ///
    /// # Errors
    ///
    /// `SpassError::Validation` if the data is empty or exceeds 100 MB.
    pub fn validate_data_size(&self, data: &DecryptedData) -> SpassResult<()> {
        const MAX_DATA_SIZE: usize = 100 * 1024 * 1024;

        if data.is_empty() {
            return Err(SpassError::Validation("Data cannot be empty".to_string()));
        }

        if data.len() > MAX_DATA_SIZE {
            return Err(SpassError::Validation(
                "Data size exceeds maximum allowed size".to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(s: &str) -> DecryptedData {
        DecryptedData::new(s.as_bytes().to_vec())
    }

    #[test]
    fn validate_v30_marker_on_line_3() {
        let v = FormatValidator::new();
        let d = data("spass_export_v1\nfoo\nnext_table\nrest\n");
        v.validate_v30_marker(&d).unwrap();
    }

    #[test]
    fn v30_marker_elsewhere_errors() {
        let v = FormatValidator::new();
        let d = data("spass_export_v1\nfoo\nbar\nnext_table\n");
        let err = v.validate_v30_marker(&d).unwrap_err();
        assert!(err.to_string().contains("line 3"));
    }

    #[test]
    fn v30_marker_missing_lines_errors() {
        let v = FormatValidator::new();
        let d = data("spass_export_v1\nfoo\n");
        let err = v.validate_v30_marker(&d).unwrap_err();
        assert!(err.to_string().contains("Insufficient"));
    }

    #[test]
    fn validate_data_size_rejects_empty() {
        let v = FormatValidator::new();
        let d = data("");
        assert!(v.validate_data_size(&d).is_err());
    }
}
