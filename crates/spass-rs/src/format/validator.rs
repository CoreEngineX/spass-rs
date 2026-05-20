//! Post-decryption structural checks for `.spass` payloads.
//!
//! Distinct from the crypto-level [`crate::crypto::validator`]:
//! that one validates *inputs* (password length, ciphertext block
//! alignment) before the AES call. This module validates *outputs*
//! after AES + PKCS7 succeed -- ensuring the decrypted bytes look
//! like a real Samsung Pass export and not a wrong-key collision.
//!
//! Two checks:
//! - Format marker on the version-specific line is exactly
//!   `next_table` ([`FormatValidator::validate_spass_marker`]).
//! - Payload size is non-empty and below a 100 MB ceiling
//!   ([`FormatValidator::validate_data_size`]).
//!
//! The marker check is the primary wrong-password tripwire: AES-CBC
//! with PKCS7 occasionally produces valid-padding output for a wrong
//! key, but the resulting bytes won't carry the magic line.

use crate::domain::{DecryptedData, SpassError, SpassResult};
use crate::format::SpassFormatVersion;
use std::io::{BufRead, BufReader, Cursor};

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

    /// Checks that the version-specific marker line is exactly
    /// `next_table`. v30 expects the marker on line 3 (index 2); v31
    /// inserts an extra metadata line and expects it on line 4
    /// (index 3). The version is passed in by the pipeline after
    /// [`crate::format::SpassFormatVersion::detect`] reads line 1.
    ///
    /// # Errors
    ///
    /// `SpassError::Validation` if the data has fewer lines than the
    /// version requires, a line can't be read, or the marker line
    /// doesn't equal `next_table`.
    pub fn validate_spass_marker(
        &self,
        data: &DecryptedData,
        version: SpassFormatVersion,
    ) -> SpassResult<()> {
        let target = version.marker_line();
        let cursor = Cursor::new(data.as_bytes());
        let reader = BufReader::new(cursor);

        for (line_num, line_result) in reader.lines().enumerate() {
            if line_num == target {
                let line_content = line_result
                    .map_err(|e| SpassError::Validation(format!("Failed to read line: {e}")))?;

                if line_content.trim() == "next_table" {
                    return Ok(());
                }
                return Err(SpassError::Validation(format!(
                    "Expected 'next_table' on line {}, found '{}'",
                    target + 1,
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
        v.validate_spass_marker(&d, SpassFormatVersion::V30)
            .unwrap();
    }

    #[test]
    fn validate_v31_marker_on_line_4() {
        let v = FormatValidator::new();
        let d = data("31\nflags\nfalse\nnext_table\nheader\n");
        v.validate_spass_marker(&d, SpassFormatVersion::V31)
            .unwrap();
    }

    #[test]
    fn v31_marker_on_v30_line_errors() {
        let v = FormatValidator::new();
        let d = data("spass_export_v1\nfoo\nnext_table\nrest\n");
        let err = v
            .validate_spass_marker(&d, SpassFormatVersion::V31)
            .unwrap_err();
        assert!(err.to_string().contains("line 4"));
    }

    #[test]
    fn v30_marker_on_v31_line_errors() {
        let v = FormatValidator::new();
        let d = data("31\nflags\nfalse\nnext_table\nheader\n");
        let err = v
            .validate_spass_marker(&d, SpassFormatVersion::V30)
            .unwrap_err();
        assert!(err.to_string().contains("line 3"));
    }

    #[test]
    fn validate_data_size_rejects_empty() {
        let v = FormatValidator::new();
        let d = data("");
        assert!(v.validate_data_size(&d).is_err());
    }
}
