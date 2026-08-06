//! Format version sentinel detection.
//!
//! Samsung Pass writes a small token on line 1 of decrypted plaintext that
//! identifies the layout used by the rest of the file. Reading this token
//! before any further parsing is what lets the pipeline dispatch to the right
//! parser without heuristics.
//!
//! Versions map to a [`WireFamily`], and the family picks the parser:
//!
//! - `WireFamily::V30Csv` -> the dedicated v30 parser
//! - `WireFamily::Schema35` -> the default schema parser, which also serves
//!   every *unknown* sentinel (`DetectedVersion::Unknown`)
//!
//! `DetectedVersion` is `pub(crate)` -- callers outside this crate get the
//! "we don't know this version" signal through
//! [`crate::domain::VersionStatus::BestEffort`] on the pipeline's outcome,
//! not directly. Keeping the unknown variant off the public type means
//! downstream `match`es don't need a wildcard arm just for an internal
//! dispatch primitive.

use crate::domain::{DecryptedData, SpassError, SpassResult};

/// Samsung Pass plaintext layout this crate recognises on line 1.
///
/// `#[non_exhaustive]` so adding `V33` etc. in a future format bump is
/// purely additive at the workspace level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "export-json", derive(serde::Serialize))]
#[non_exhaustive]
pub enum SpassFormatVersion {
    /// Original 5-column comma-delimited plaintext CSV; Samsung writes the
    /// literal `spass_export_v1` on line 1 for this format.
    V30,
    /// 35-column semicolon-delimited Base64-encoded CSV with `&&&NULL&&&`
    /// absent-value sentinel. First seen 2026-05.
    V31,
    /// Sentinel `"32"`, layout byte-identical to V31 -- confirmed against a
    /// complete real export (preamble, header, row widths, table
    /// boundaries). First seen 2026-08.
    V32,
}

/// Which parser a version routes to. A future same-layout version extends
/// the sentinel match in [`SpassFormatVersion::detect`] and the arm in
/// [`SpassFormatVersion::wire_family`] -- no parser code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WireFamily {
    /// Comma-delimited plaintext CSV with the `next_table` marker pinned to
    /// line 3. v30 only.
    V30Csv,
    /// 35-column semicolon + Base64 family served by the default schema
    /// parser: v31, v32, and every unknown sentinel.
    Schema35,
}

/// Outcome of running [`SpassFormatVersion::detect`]. Internal dispatch
/// primitive -- the public-facing version state lives on
/// [`crate::domain::VersionStatus`].
#[derive(Debug, Clone)]
pub(crate) enum DetectedVersion {
    /// Line-1 sentinel matched a version in the table.
    Known(SpassFormatVersion),
    /// Line-1 sentinel didn't match any known version. The captured string
    /// is preserved verbatim (post-trim) so the contribution loop names the
    /// real value the user has on disk.
    Unknown(String),
}

impl SpassFormatVersion {
    /// Reads the line-1 sentinel from decrypted plaintext.
    ///
    /// Hard-errors only when line 1 is empty or not valid UTF-8 (a missing
    /// sentinel is a malformed file, not a new format version). Any other
    /// string -- including future Samsung sentinels like `"33"` -- returns
    /// `DetectedVersion::Unknown(s)` so the schema parser can have a go.
    ///
    /// # Errors
    ///
    /// `SpassError::Validation` if line 1 is empty or non-UTF-8.
    pub(crate) fn detect(plaintext: &DecryptedData) -> SpassResult<DetectedVersion> {
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
            "spass_export_v1" => Ok(DetectedVersion::Known(Self::V30)),
            "31" => Ok(DetectedVersion::Known(Self::V31)),
            "32" => Ok(DetectedVersion::Known(Self::V32)),
            "" => Err(SpassError::Validation(
                "Format version missing on line 1".to_string(),
            )),
            other => Ok(DetectedVersion::Unknown(other.to_string())),
        }
    }

    /// The parser family this version routes to.
    pub(crate) fn wire_family(self) -> WireFamily {
        match self {
            Self::V30 => WireFamily::V30Csv,
            Self::V31 | Self::V32 => WireFamily::Schema35,
        }
    }

    /// Line-1 sentinel as Samsung writes it. Flows into the schema parser's
    /// report so error diagnostics name the real on-disk value even on the
    /// known-version path.
    pub(crate) fn sentinel_str(self) -> &'static str {
        match self {
            Self::V30 => "spass_export_v1",
            Self::V31 => "31",
            Self::V32 => "32",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(s: &str) -> DecryptedData {
        DecryptedData::new(s.as_bytes().to_vec())
    }

    fn expect_known(d: &DecryptedData) -> SpassFormatVersion {
        match SpassFormatVersion::detect(d).unwrap() {
            DetectedVersion::Known(v) => v,
            DetectedVersion::Unknown(s) => panic!("expected Known, got Unknown({s})"),
        }
    }

    fn expect_unknown(d: &DecryptedData) -> String {
        match SpassFormatVersion::detect(d).unwrap() {
            DetectedVersion::Unknown(s) => s,
            DetectedVersion::Known(v) => panic!("expected Unknown, got Known({v:?})"),
        }
    }

    #[test]
    fn detect_v30() {
        let d = data("spass_export_v1\nheader\nnext_table\n");
        assert_eq!(expect_known(&d), SpassFormatVersion::V30);
    }

    #[test]
    fn detect_v30_with_trailing_carriage_return() {
        let d = data("spass_export_v1\r\nheader\r\nnext_table\r\n");
        assert_eq!(expect_known(&d), SpassFormatVersion::V30);
    }

    #[test]
    fn detect_v31() {
        let d = data("31\ntrue;false;false;false\nfalse\nnext_table\n");
        assert_eq!(expect_known(&d), SpassFormatVersion::V31);
    }

    #[test]
    fn detect_v31_with_trailing_carriage_return() {
        let d = data("31\r\ntrue;false;false;false\r\n");
        assert_eq!(expect_known(&d), SpassFormatVersion::V31);
    }

    #[test]
    fn detect_v32() {
        let d = data("32\ntrue;false;false;false\nfalse\nnext_table\n");
        assert_eq!(expect_known(&d), SpassFormatVersion::V32);
    }

    #[test]
    fn detect_unknown_version_returns_unknown_variant() {
        let d = data("33\nfoo\n");
        assert_eq!(expect_unknown(&d), "33");
    }

    #[test]
    fn detect_legacy_numeric_30_is_unknown_not_v30() {
        // Real v30 files write "spass_export_v1", not "30". A literal "30"
        // landing here means Samsung shipped a new format we haven't taught
        // support for -- route through the schema parser as unknown.
        let d = data("30\nheader\nnext_table\n");
        assert_eq!(expect_unknown(&d), "30");
    }

    #[test]
    fn detect_garbage_is_unknown() {
        let d = data("not_a_number\n");
        assert_eq!(expect_unknown(&d), "not_a_number");
    }

    #[test]
    fn detect_empty_first_line_errors() {
        let d = data("\nfoo\n");
        let err = SpassFormatVersion::detect(&d).unwrap_err();
        assert!(err.to_string().contains("missing"));
    }

    #[test]
    fn wire_families() {
        assert_eq!(SpassFormatVersion::V30.wire_family(), WireFamily::V30Csv);
        assert_eq!(SpassFormatVersion::V31.wire_family(), WireFamily::Schema35);
        assert_eq!(SpassFormatVersion::V32.wire_family(), WireFamily::Schema35);
    }

    #[test]
    fn sentinel_strings_round_trip_through_detect() {
        for v in [
            SpassFormatVersion::V30,
            SpassFormatVersion::V31,
            SpassFormatVersion::V32,
        ] {
            let d = data(&format!("{}\nrest\n", v.sentinel_str()));
            assert_eq!(expect_known(&d), v);
        }
    }
}
