//! v31 tokenization: 35-column split, Base64-decode of the 5 columns we keep,
//! `&&&NULL&&&` sentinel mapping, `next_table` early-stop for the second-table
//! boundary.
//!
//! v31 plaintext stores 35 columns per row but the workspace only consumes 5
//! (`url`, `username`, `password`, `name`, `note`). We still validate the row
//! width (so format drift is loud) but only Base64-decode the 5 columns we
//! project to `PasswordEntry`. The other 30 are skipped.
//!
//! [`decode_v31_cell`] is the per-cell primitive (Base64 + `&&&NULL&&&`
//! mapping + UTF-8 validate). Both the strict v31 parser (hardcoded indices)
//! and the lenient parser at `parser/lenient.rs` (name-resolved indices) use
//! it so the wire-decoding rules don't drift between them.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

use crate::domain::{SpassError, SpassResult};

/// v31 row width. Samsung writes exactly this many fields per row.
pub(crate) const V31_COLUMN_COUNT: usize = 35;

/// Sentinel byte sequence Samsung writes for absent values. At the wire it's
/// Base64-encoded (`JiYmTlVMTCYmJg==`); after decoding it's these 10 ASCII
/// bytes. The tokenizer maps it to the empty string.
const ABSENT_SENTINEL: &[u8] = b"&&&NULL&&&";

/// Column indices for the 5 fields we project to `PasswordEntry`. See
/// `spass-docs/spass-core-api.md` §3.5 for the field-mapping rationale (why
/// `username_value` not `username_element`, etc.).
const COL_ORIGIN_URL: usize = 1;
const COL_USERNAME_VALUE: usize = 4;
const COL_PASSWORD_VALUE: usize = 7;
const COL_TITLE: usize = 17;
const COL_CREDENTIAL_MEMO: usize = 31;

/// Decode one v31 wire cell. Empty input and the absent-sentinel both
/// collapse to the empty string; anything else is Base64-decoded and
/// UTF-8-validated.
///
/// `row_idx` and `col_idx` are 0-based and only used for error messages.
pub(crate) fn decode_v31_cell(
    field_str: &str,
    row_idx: usize,
    col_idx: usize,
) -> SpassResult<String> {
    if field_str.is_empty() {
        return Ok(String::new());
    }

    let decoded = BASE64.decode(field_str).map_err(|e| {
        SpassError::Parsing(format!(
            "v31 row {row_idx}: column {col_idx} Base64 decode failed: {e}"
        ))
    })?;

    if decoded.as_slice() == ABSENT_SENTINEL {
        return Ok(String::new());
    }

    String::from_utf8(decoded).map_err(|_| {
        SpassError::Parsing(format!(
            "v31 row {row_idx}: column {col_idx} bytes are not valid UTF-8"
        ))
    })
}

/// Decoded view of one v31 row, projected to the 5 fields we keep.
#[derive(Debug, Default)]
pub(crate) struct V31Row {
    pub(crate) origin_url: String,
    pub(crate) username_value: String,
    pub(crate) password_value: String,
    pub(crate) title: String,
    pub(crate) credential_memo: String,
}

/// Tokenize one v31 row line. Splits on `;`, validates exactly 35 fields,
/// Base64-decodes the 5 columns we project, maps `&&&NULL&&&` and empty
/// fields to the empty string. The row index is 0-based within the data
/// section and only used for error messages.
pub(crate) fn tokenize_row(line: &str, row_idx: usize) -> SpassResult<V31Row> {
    let mut row = V31Row::default();
    let mut count: usize = 0;

    for (i, field_str) in line.split(';').enumerate() {
        if i >= V31_COLUMN_COUNT {
            return Err(SpassError::Parsing(format!(
                "v31 row {row_idx} has more than {V31_COLUMN_COUNT} fields"
            )));
        }
        count = i + 1;

        let target = match i {
            COL_ORIGIN_URL => &mut row.origin_url,
            COL_USERNAME_VALUE => &mut row.username_value,
            COL_PASSWORD_VALUE => &mut row.password_value,
            COL_TITLE => &mut row.title,
            COL_CREDENTIAL_MEMO => &mut row.credential_memo,
            _ => continue,
        };

        *target = decode_v31_cell(field_str, row_idx, i)?;
    }

    if count != V31_COLUMN_COUNT {
        return Err(SpassError::Parsing(format!(
            "v31 row {row_idx} has {count} fields, expected {V31_COLUMN_COUNT}"
        )));
    }

    Ok(row)
}

/// Splits plaintext at the first `next_table` marker. Returns `(header,
/// data_lines)` with no validation of the header shape -- callers
/// (strict v31 and the lenient parser) impose their own checks.
///
/// The iterator stops at the next `next_table` marker (Samsung writes
/// additional tables, e.g. secure notes, after the credentials block).
pub(crate) fn split_v31_sections_unchecked(
    plaintext: &str,
) -> SpassResult<(&str, impl Iterator<Item = &str>)> {
    let after_marker = plaintext
        .split_once("next_table")
        .map(|(_, rest)| rest)
        .ok_or_else(|| {
            SpassError::Parsing("v31 plaintext missing 'next_table' marker".to_string())
        })?;

    let mut lines = after_marker.trim_start_matches(['\r', '\n']).lines();
    let header = lines
        .next()
        .ok_or_else(|| SpassError::Parsing("v31 plaintext missing header line".to_string()))?;

    let data_lines = lines.take_while(|line| line.trim() != "next_table");

    Ok((header, data_lines))
}

/// Same as [`split_v31_sections_unchecked`] plus the strict-v31 header shape
/// checks: exactly 35 semicolon-separated columns, must start with
/// `_id;origin_url;`. Used by [`super::csv::SpassCsvV31Parser`].
///
/// The boundary work is duplicated rather than delegated because each
/// function's `impl Iterator` is its own opaque type -- can't propagate one
/// through another without naming the concrete type.
pub(crate) fn split_v31_sections(
    plaintext: &str,
) -> SpassResult<(&str, impl Iterator<Item = &str>)> {
    let after_marker = plaintext
        .split_once("next_table")
        .map(|(_, rest)| rest)
        .ok_or_else(|| {
            SpassError::Parsing("v31 plaintext missing 'next_table' marker".to_string())
        })?;

    let mut lines = after_marker.trim_start_matches(['\r', '\n']).lines();
    let header = lines
        .next()
        .ok_or_else(|| SpassError::Parsing("v31 plaintext missing header line".to_string()))?;

    let header_count = header.split(';').count();
    if header_count != V31_COLUMN_COUNT {
        return Err(SpassError::Parsing(format!(
            "v31 header has {header_count} columns, expected {V31_COLUMN_COUNT}"
        )));
    }
    if !header.starts_with("_id;origin_url;") {
        return Err(SpassError::Parsing(
            "v31 header does not start with `_id;origin_url;`".to_string(),
        ));
    }

    let data_lines = lines.take_while(|line| line.trim() != "next_table");

    Ok((header, data_lines))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(s: &[u8]) -> String {
        BASE64.encode(s)
    }

    /// Build a 35-field semicolon row from a list of (index, value) pairs.
    /// All other fields are empty.
    fn row_with(fields: &[(usize, &str)]) -> String {
        let mut parts: Vec<String> = (0..V31_COLUMN_COUNT).map(|_| String::new()).collect();
        for (i, v) in fields {
            parts[*i] = b64(v.as_bytes());
        }
        parts.join(";")
    }

    fn canonical_header() -> String {
        let cols = [
            "_id",
            "origin_url",
            "action_url",
            "username_element",
            "username_value",
            "id_tz_enc",
            "password_element",
            "password_value",
            "pw_tz_enc",
            "host_url",
            "ssl_valid",
            "preferred",
            "blacklisted_by_user",
            "use_additional_auth",
            "cm_api_support",
            "created_time",
            "modified_time",
            "title",
            "favicon",
            "source_type",
            "app_name",
            "package_name",
            "package_signature",
            "reserved_1",
            "reserved_2",
            "reserved_3",
            "reserved_4",
            "reserved_5",
            "reserved_6",
            "reserved_7",
            "reserved_8",
            "credential_memo",
            "otp",
            "root_id",
            "parent_id",
        ];
        cols.join(";")
    }

    #[test]
    fn tokenize_basic_row() {
        let line = row_with(&[
            (COL_ORIGIN_URL, "https://example.com"),
            (COL_USERNAME_VALUE, "alice"),
            (COL_PASSWORD_VALUE, "secret"),
            (COL_TITLE, "Example"),
            (COL_CREDENTIAL_MEMO, "my note"),
        ]);
        let row = tokenize_row(&line, 0).unwrap();
        assert_eq!(row.origin_url, "https://example.com");
        assert_eq!(row.username_value, "alice");
        assert_eq!(row.password_value, "secret");
        assert_eq!(row.title, "Example");
        assert_eq!(row.credential_memo, "my note");
    }

    #[test]
    fn null_sentinel_decodes_to_empty_string() {
        let line = row_with(&[
            (COL_USERNAME_VALUE, "alice"),
            (COL_CREDENTIAL_MEMO, "&&&NULL&&&"),
        ]);
        let row = tokenize_row(&line, 0).unwrap();
        assert_eq!(row.username_value, "alice");
        assert_eq!(row.credential_memo, "");
    }

    #[test]
    fn empty_field_is_empty_string() {
        let line: String = std::iter::repeat(";").take(V31_COLUMN_COUNT - 1).collect();
        let row = tokenize_row(&line, 0).unwrap();
        assert_eq!(row.origin_url, "");
        assert_eq!(row.username_value, "");
    }

    #[test]
    fn wrong_column_count_errors() {
        let line = ";;;;;;";
        let err = tokenize_row(line, 7)
            .err()
            .expect("expected wrong-column-count error");
        assert!(err.to_string().contains("row 7"));
        assert!(err.to_string().contains("expected 35"));
    }

    #[test]
    fn malformed_base64_errors() {
        let line = row_with(&[(COL_ORIGIN_URL, "")]); // start with valid then patch
        let mut parts: Vec<&str> = line.split(';').collect();
        parts[COL_ORIGIN_URL] = "!!!not-base64!!!";
        let bad_line = parts.join(";");
        let err = tokenize_row(&bad_line, 3)
            .err()
            .expect("expected base64 error");
        assert!(err.to_string().contains("row 3"));
        assert!(err.to_string().contains("Base64"));
    }

    #[test]
    fn split_v31_sections_happy_path() {
        let header = canonical_header();
        let plaintext = format!("31\nflags\nfalse\nnext_table\n{header}\nrow1\nrow2\n");
        let (h, lines) = split_v31_sections(&plaintext).unwrap();
        assert_eq!(h, header);
        let lines: Vec<&str> = lines.collect();
        assert_eq!(lines, vec!["row1", "row2"]);
    }

    #[test]
    fn split_v31_sections_stops_at_second_next_table_marker() {
        // Samsung writes additional tables (notes, etc.) after the credentials
        // block, separated by another `next_table`. Our iterator must stop
        // before tokenising those rows as credentials.
        let header = canonical_header();
        let plaintext = format!(
            "31\nflags\nfalse\nnext_table\n{header}\nrow1\nrow2\nnext_table\nnote_table_header\nnote_row1\n"
        );
        let (_, lines) = split_v31_sections(&plaintext).unwrap();
        let lines: Vec<&str> = lines.collect();
        assert_eq!(lines, vec!["row1", "row2"]);
    }

    #[test]
    fn split_v31_sections_rejects_wrong_header_width() {
        let plaintext = "31\nflags\nfalse\nnext_table\n_id;origin_url\nrow1";
        let err = split_v31_sections(plaintext)
            .err()
            .expect("expected header-width error");
        assert!(err.to_string().contains("expected 35"));
    }

    #[test]
    fn split_v31_sections_rejects_unexpected_header_prefix() {
        let cols: Vec<&str> = (0..V31_COLUMN_COUNT).map(|_| "x").collect();
        let header = cols.join(";");
        let plaintext = format!("31\nflags\nfalse\nnext_table\n{header}\nrow1\n");
        let err = split_v31_sections(&plaintext)
            .err()
            .expect("expected header-prefix error");
        assert!(err.to_string().contains("does not start with"));
    }
}
