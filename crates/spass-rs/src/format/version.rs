//! Format version sentinel detection.
//!
//! Samsung Pass writes a small integer on line 1 of decrypted plaintext that
//! identifies the layout used by the rest of the file. Reading this sentinel
//! before any further parsing is what lets the pipeline dispatch to the right
//! parser without heuristics.

use crate::domain::{DecryptedData, SpassError, SpassResult};

/// `.spass` plaintext format version sentinel (line 1 of decrypted data).
///
/// `#[non_exhaustive]` so adding `V32` etc. in a future format bump is purely
/// additive at the workspace level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SpassFormatVersion {
    /// Original 5-column comma-delimited plaintext CSV.
    V30,
    /// 35-column semicolon-delimited Base64-encoded CSV with `&&&NULL&&&`
    /// absent-value sentinel. First seen 2026-05.
    V31,
}

impl SpassFormatVersion {
    /// Detects the format version from the first line of decrypted plaintext.
    ///
    /// # Errors
    ///
    /// `SpassError::Validation` if line 1 is missing or names a version we
    /// don't support.
    pub fn detect(plaintext: &DecryptedData) -> SpassResult<Self> {
        let bytes = plaintext.as_bytes();
        let first_line_end = bytes
            .iter()
            .position(|&b| b == b'\n')
            .unwrap_or(bytes.len());
        let first_line = std::str::from_utf8(&bytes[..first_line_end])
            .map_err(|_| {
                SpassError::Validation("Format version line is not valid UTF-8".to_string())
            })?
            .trim();

        match first_line {
            "spass_export_v1" => Ok(Self::V30),
            "31" => Ok(Self::V31),
            "" => Err(SpassError::Validation(
                "Format version missing on line 1".to_string(),
            )),
            other => Err(SpassError::Validation(format!(
                "Unsupported .spass format version: {other}"
            ))),
        }
    }

    /// 0-indexed line number where `next_table` is expected for this version.
    ///
    /// v30 puts the marker on line 3 (index 2); v31 inserts an extra metadata
    /// line and pushes the marker to line 4 (index 3).
    #[must_use]
    pub(crate) fn marker_line(self) -> usize {
        match self {
            Self::V30 => 2,
            Self::V31 => 3,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(s: &str) -> DecryptedData {
        DecryptedData::new(s.as_bytes().to_vec())
    }

    #[test]
    fn detect_v30() {
        let d = data("spass_export_v1\nheader\nnext_table\n");
        assert_eq!(
            SpassFormatVersion::detect(&d).unwrap(),
            SpassFormatVersion::V30
        );
    }

    #[test]
    fn detect_v30_with_trailing_carriage_return() {
        let d = data("spass_export_v1\r\nheader\r\nnext_table\r\n");
        assert_eq!(
            SpassFormatVersion::detect(&d).unwrap(),
            SpassFormatVersion::V30
        );
    }

    #[test]
    fn detect_v31() {
        let d = data("31\ntrue;false;false;false\nfalse\nnext_table\n");
        assert_eq!(
            SpassFormatVersion::detect(&d).unwrap(),
            SpassFormatVersion::V31
        );
    }

    #[test]
    fn detect_v31_with_trailing_carriage_return() {
        let d = data("31\r\ntrue;false;false;false\r\n");
        assert_eq!(
            SpassFormatVersion::detect(&d).unwrap(),
            SpassFormatVersion::V31
        );
    }

    #[test]
    fn detect_unsupported_version_errors() {
        let d = data("32\nfoo\n");
        let err = SpassFormatVersion::detect(&d).unwrap_err();
        assert!(err.to_string().contains("Unsupported"));
        assert!(err.to_string().contains("32"));
    }

    #[test]
    fn detect_legacy_numeric_30_no_longer_recognized() {
        let d = data("30\nheader\nnext_table\n");
        let err = SpassFormatVersion::detect(&d).unwrap_err();
        assert!(err.to_string().contains("Unsupported"));
        assert!(err.to_string().contains("30"));
    }

    #[test]
    fn detect_empty_first_line_errors() {
        let d = data("\nfoo\n");
        let err = SpassFormatVersion::detect(&d).unwrap_err();
        assert!(err.to_string().contains("missing"));
    }

    #[test]
    fn detect_garbage_errors() {
        let d = data("not_a_number\n");
        let err = SpassFormatVersion::detect(&d).unwrap_err();
        assert!(err.to_string().contains("Unsupported"));
    }

    #[test]
    fn marker_line_indices() {
        assert_eq!(SpassFormatVersion::V30.marker_line(), 2);
        assert_eq!(SpassFormatVersion::V31.marker_line(), 3);
    }
}
