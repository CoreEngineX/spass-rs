//! Schema-driven fallback parser for `.spass` files whose line-1 sentinel
//! this crate doesn't strictly know.
//!
//! The pipeline routes here when the internal version-sentinel detector
//! returns its `Unknown` arm. The parser:
//!
//! 1. Reads the v31-shape header after the `next_table` marker (no strict
//!    35-column check -- that's the whole point).
//! 2. Walks the header looking for the 5 canonical column names we project
//!    to `PasswordEntry` (`origin_url`, `username_value`, `password_value`,
//!    `title`, `credential_memo`).
//! 3. If all 5 are present, tokenizes each row by looked-up index and
//!    returns the entries plus a [`BestEffortReport`] for the contribution
//!    loop.
//! 4. If any required column is missing, returns
//!    `SpassError::UnknownVersionUnparseable(report)` so the consumer can
//!    still build a contact URL.
//!
//! Unknown columns (the 30+ Samsung writes that we don't care about) are
//! collected for diagnostics and otherwise skipped silently -- consistent
//! with how the strict v31 parser treats them today.
//!
//! Not implemented as a [`crate::parser::DataParser`]: the trait's `parse`
//! returns only `PasswordEntryCollection`, with no room for the report. The
//! pipeline invokes [`LenientV31Parser::parse`] directly with the captured
//! sentinel string.

use crate::domain::{
    BestEffortReport, PasswordEntry, PasswordEntryCollection, SpassError, SpassResult,
};
use crate::parser::v31::tokenize::{decode_v31_cell, split_v31_sections_unchecked};

/// Canonical v31 column names the lenient parser keys on, in the order
/// `PasswordEntry::new` expects its arguments. Order matters for
/// diagnostics; the values must match what Samsung emits in the v31
/// header (lower-snake-case, exact match).
const REQUIRED_COLUMNS: [&str; 5] = [
    "origin_url",
    "username_value",
    "password_value",
    "title",
    "credential_memo",
];

const SLOT_ORIGIN_URL: usize = 0;
const SLOT_USERNAME_VALUE: usize = 1;
const SLOT_PASSWORD_VALUE: usize = 2;
const SLOT_TITLE: usize = 3;
const SLOT_CREDENTIAL_MEMO: usize = 4;

/// Resolved name -> column index for each of the 5 required columns,
/// plus the diagnostic columns we collected along the way.
struct V31ColumnLookup {
    indices: [usize; 5],
    max_required_index: usize,
    recognized_columns: Vec<String>,
    unknown_columns: Vec<String>,
}

/// What `V31ColumnLookup::from_header` populates when at least one required
/// column was absent. Carries the same diagnostic data the success path
/// uses, but skips the resolved indices because there's nothing to parse.
///
/// `_columns` suffix is load-bearing here; flowing into `BestEffortReport`'s
/// fields of the same name.
#[allow(clippy::struct_field_names)]
struct V31LookupFailure {
    recognized_columns: Vec<String>,
    missing_required_columns: Vec<String>,
    unknown_columns: Vec<String>,
}

impl V31ColumnLookup {
    fn from_header(header: &str) -> Result<Self, V31LookupFailure> {
        let mut indices: [Option<usize>; 5] = [None; 5];
        let mut recognized = Vec::with_capacity(REQUIRED_COLUMNS.len());
        let mut unknown = Vec::new();

        for (i, name) in header.split(';').map(str::trim).enumerate() {
            if let Some(slot) = REQUIRED_COLUMNS.iter().position(|canon| *canon == name) {
                // First-write wins if Samsung ever ships a duplicate canonical
                // name in the same header. Defensive against pathological input.
                if indices[slot].is_none() {
                    indices[slot] = Some(i);
                    recognized.push(REQUIRED_COLUMNS[slot].to_string());
                }
            } else {
                unknown.push(name.to_string());
            }
        }

        match indices {
            [Some(origin_url), Some(username_value), Some(password_value), Some(title), Some(credential_memo)] =>
            {
                let resolved = [
                    origin_url,
                    username_value,
                    password_value,
                    title,
                    credential_memo,
                ];
                let max_required_index = resolved.iter().copied().max().unwrap_or(0);
                Ok(Self {
                    indices: resolved,
                    max_required_index,
                    recognized_columns: recognized,
                    unknown_columns: unknown,
                })
            }
            _ => Err(V31LookupFailure {
                missing_required_columns: REQUIRED_COLUMNS
                    .iter()
                    .zip(indices.iter())
                    .filter_map(|(name, idx)| {
                        if idx.is_none() {
                            Some((*name).to_string())
                        } else {
                            None
                        }
                    })
                    .collect(),
                recognized_columns: recognized,
                unknown_columns: unknown,
            }),
        }
    }
}

/// Best-effort parser for v31-shape `.spass` files with an unrecognised
/// version sentinel.
pub(crate) struct LenientV31Parser;

impl LenientV31Parser {
    pub(crate) fn new() -> Self {
        Self
    }

    /// Parses `plaintext` as v31-shape, resolving the 5 required columns
    /// by name. `sentinel` is the line-1 string captured upstream; it
    /// only flows into the returned [`BestEffortReport`] for the
    /// contribution loop and doesn't affect parsing.
    ///
    /// # Errors
    ///
    /// - [`SpassError::Parsing`] if the file has no `next_table` marker
    ///   or a row's wire shape is malformed (Base64, UTF-8).
    /// - [`SpassError::UnknownVersionUnparseable`] when at least one of
    ///   the 5 required columns is absent from the header -- carries the
    ///   diagnostic.
    //
    // `&self` is kept so the pipeline can stash a parser instance and call
    // `.parse(...)` symmetrically with the strict parsers. The parser itself
    // is stateless today but might gain configuration (e.g. tracing level)
    // later without an API break.
    #[allow(clippy::unused_self)]
    pub(crate) fn parse(
        &self,
        sentinel: &str,
        plaintext: &[u8],
    ) -> SpassResult<(PasswordEntryCollection, BestEffortReport)> {
        let text = std::str::from_utf8(plaintext)
            .map_err(|_| SpassError::Parsing("Decrypted data is not valid UTF-8".to_string()))?;

        let (header, data_lines) = split_v31_sections_unchecked(text)?;

        let lookup = V31ColumnLookup::from_header(header).map_err(|failure| {
            SpassError::UnknownVersionUnparseable(Box::new(BestEffortReport {
                sentinel: sentinel.to_string(),
                header_line: header.to_string(),
                recognized_columns: failure.recognized_columns,
                missing_required_columns: failure.missing_required_columns,
                unknown_columns: failure.unknown_columns,
                entries_extracted: 0,
            }))
        })?;

        let header_owned = header.to_string();
        let mut collection = PasswordEntryCollection::with_capacity(text.len() / 600);
        let max_required = lookup.max_required_index;

        for (row_idx, line) in data_lines.enumerate() {
            if line.is_empty() {
                continue;
            }

            let fields: Vec<&str> = line.split(';').collect();
            if fields.len() <= max_required {
                return Err(SpassError::Parsing(format!(
                    "lenient v31 row {row_idx} has {} fields; need at least {}",
                    fields.len(),
                    max_required + 1
                )));
            }

            let url = decode_v31_cell(
                fields[lookup.indices[SLOT_ORIGIN_URL]],
                row_idx,
                lookup.indices[SLOT_ORIGIN_URL],
            )?;
            let username = decode_v31_cell(
                fields[lookup.indices[SLOT_USERNAME_VALUE]],
                row_idx,
                lookup.indices[SLOT_USERNAME_VALUE],
            )?;
            let password = decode_v31_cell(
                fields[lookup.indices[SLOT_PASSWORD_VALUE]],
                row_idx,
                lookup.indices[SLOT_PASSWORD_VALUE],
            )?;
            let name = decode_v31_cell(
                fields[lookup.indices[SLOT_TITLE]],
                row_idx,
                lookup.indices[SLOT_TITLE],
            )?;
            let note = decode_v31_cell(
                fields[lookup.indices[SLOT_CREDENTIAL_MEMO]],
                row_idx,
                lookup.indices[SLOT_CREDENTIAL_MEMO],
            )?;

            collection.push(PasswordEntry::new(url, username, password, name, note));
        }

        let report = BestEffortReport {
            sentinel: sentinel.to_string(),
            header_line: header_owned,
            recognized_columns: lookup.recognized_columns,
            missing_required_columns: Vec::new(),
            unknown_columns: lookup.unknown_columns,
            entries_extracted: collection.len(),
        };

        Ok((collection, report))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

    fn b64(s: &str) -> String {
        BASE64.encode(s.as_bytes())
    }

    /// Builds a synthetic v31-shape file with a custom sentinel and column
    /// layout. `columns` is the header (semicolon-joined column names);
    /// each row in `rows` is a list of `(column_name, value)` pairs --
    /// missing column names become empty wire fields.
    fn make_file(sentinel: &str, columns: &[&str], rows: &[&[(&str, &str)]]) -> Vec<u8> {
        let header = columns.join(";");
        let mut out = format!("{sentinel}\nfoo\nbar\nnext_table\n{header}\n");
        for row in rows {
            let mut parts: Vec<String> = columns.iter().map(|_| String::new()).collect();
            for (name, value) in *row {
                let col_idx = columns
                    .iter()
                    .position(|c| c == name)
                    .expect("test column name not in header");
                parts[col_idx] = b64(value);
            }
            out.push_str(&parts.join(";"));
            out.push('\n');
        }
        out.into_bytes()
    }

    fn canonical_columns() -> Vec<&'static str> {
        vec![
            "_id",
            "origin_url",
            "action_url",
            "username_element",
            "username_value",
            "password_element",
            "password_value",
            "title",
            "credential_memo",
        ]
    }

    #[test]
    fn parses_canonical_v31_shape_with_unknown_sentinel() {
        let columns = canonical_columns();
        let bytes = make_file(
            "32",
            &columns,
            &[&[
                ("origin_url", "https://example.com"),
                ("username_value", "alice"),
                ("password_value", "secret"),
                ("title", "Example"),
                ("credential_memo", "my note"),
            ]],
        );

        let (entries, report) = LenientV31Parser::new().parse("32", &bytes).unwrap();
        assert_eq!(entries.len(), 1);
        let e = &entries.entries()[0];
        assert_eq!(e.url.as_str(), "https://example.com");
        assert_eq!(e.username.as_str(), "alice");
        assert_eq!(e.password.as_str(), "secret");
        assert_eq!(e.name.as_str(), "Example");
        assert_eq!(e.note.as_str(), "my note");

        assert_eq!(report.sentinel, "32");
        assert_eq!(report.entries_extracted, 1);
        assert!(report.missing_required_columns.is_empty());
        // All 5 canonical names recognized.
        assert_eq!(report.recognized_columns.len(), 5);
    }

    #[test]
    fn survives_reordered_columns() {
        // title earlier than origin_url, password_value later, etc.
        let columns = vec![
            "title",
            "_id",
            "credential_memo",
            "password_value",
            "origin_url",
            "username_value",
        ];
        let bytes = make_file(
            "32",
            &columns,
            &[&[
                ("origin_url", "https://x.com"),
                ("username_value", "bob"),
                ("password_value", "hunter2"),
                ("title", "X"),
                ("credential_memo", ""),
            ]],
        );

        let (entries, _report) = LenientV31Parser::new().parse("32", &bytes).unwrap();
        let e = &entries.entries()[0];
        assert_eq!(e.url.as_str(), "https://x.com");
        assert_eq!(e.name.as_str(), "X");
        assert_eq!(e.password.as_str(), "hunter2");
    }

    #[test]
    fn fails_with_diagnostic_when_required_column_missing() {
        // password_value column removed; the rest present.
        let columns = vec![
            "_id",
            "origin_url",
            "username_value",
            // no password_value
            "title",
            "credential_memo",
        ];
        let bytes = make_file("32", &columns, &[]);

        let err = LenientV31Parser::new().parse("32", &bytes).unwrap_err();
        match err {
            SpassError::UnknownVersionUnparseable(report) => {
                assert_eq!(report.sentinel, "32");
                assert_eq!(report.missing_required_columns, vec!["password_value"]);
                // The other 4 should be in recognized.
                assert!(report
                    .recognized_columns
                    .contains(&"origin_url".to_string()));
                assert!(report.recognized_columns.contains(&"title".to_string()));
                assert_eq!(report.entries_extracted, 0);
            }
            other => panic!("expected UnknownVersionUnparseable, got {other:?}"),
        }
    }

    #[test]
    fn collects_unknown_columns() {
        let mut columns = canonical_columns();
        columns.push("brand_new_column_a");
        columns.push("brand_new_column_b");
        let bytes = make_file(
            "32",
            &columns,
            &[&[
                ("origin_url", "https://a.com"),
                ("username_value", "u"),
                ("password_value", "p"),
                ("title", "A"),
                ("credential_memo", "n"),
            ]],
        );

        let (_, report) = LenientV31Parser::new().parse("32", &bytes).unwrap();
        assert!(report
            .unknown_columns
            .contains(&"brand_new_column_a".to_string()));
        assert!(report
            .unknown_columns
            .contains(&"brand_new_column_b".to_string()));
    }

    #[test]
    fn no_next_table_marker_errors() {
        let bytes = b"32\nfoo\nbar\nbaz\n".to_vec();
        let err = LenientV31Parser::new().parse("32", &bytes).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("next_table"), "got: {msg}");
    }

    #[test]
    fn row_shorter_than_max_lookup_index_errors() {
        let columns = canonical_columns();
        // build a row that drops the last (largest-index) column
        let header = columns.join(";");
        let mut bytes = format!("32\nfoo\nbar\nnext_table\n{header}\n");
        // Only 5 fields when header has 9 columns.
        bytes.push_str("a;b;c;d;e\n");

        let err = LenientV31Parser::new()
            .parse("32", bytes.as_bytes())
            .unwrap_err();
        assert!(err.to_string().contains("need at least"));
    }
}
