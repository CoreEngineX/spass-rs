//! Default schema-driven parser for the 35-column `.spass` family
//! (`WireFamily::Schema35`): v31, v32, and every unknown sentinel.
//!
//! One parser, two statuses. The pipeline routes known family sentinels
//! (`"31"`, `"32"`) here and reports `VersionStatus::Known`; unknown
//! sentinels take the same path and report `VersionStatus::BestEffort`
//! with the diagnostic for the contribution loop. There is no separate
//! strict parser: the 5 projected columns are resolved **by name** from
//! the header, which survives column reordering and insertion, and fails
//! loudly (with a report) if a column we keep is renamed -- protection a
//! positional parser cannot give.
//!
//! Wire shape: semicolon-delimited rows after a `next_table` marker line,
//! each cell Base64-encoded, with the `&&&NULL&&&` sentinel for absent
//! values. Cells outside the 5 resolved columns are never Base64-decoded
//! and never allocated; row iteration stops at the highest resolved
//! column index.
//!
//! [`SchemaParser::parse_with_report`] is the pipeline entry point (it
//! needs the sentinel for the report and returns the report alongside
//! the entries). The [`DataParser`] impl serves the [`ParserRegistry`]
//! tooling surface, where only the entries matter.
//!
//! [`ParserRegistry`]: crate::parser::ParserRegistry

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

use crate::domain::{
    BestEffortReport, PasswordEntry, PasswordEntryCollection, SpassError, SpassResult,
};
use crate::parser::trait_def::{DataParser, FormatId, ParserSchema};

/// Canonical column names resolved from the header, in the order
/// [`PasswordEntry::new`] expects its arguments. The values must match
/// what Samsung emits in the header (lower-snake-case, exact match).
const REQUIRED_COLUMNS: [&str; 5] = [
    "origin_url",
    "username_value",
    "password_value",
    "title",
    "credential_memo",
];

/// Sentinel byte sequence Samsung writes for absent values. At the wire it's
/// Base64-encoded (`JiYmTlVMTCYmJg==`); after decoding it's these 10 ASCII
/// bytes. The tokenizer maps it to the empty string.
const ABSENT_SENTINEL: &[u8] = b"&&&NULL&&&";

/// Decode one wire cell. Empty input and the absent-sentinel both
/// collapse to the empty string; anything else is Base64-decoded and
/// UTF-8-validated.
///
/// `row_idx` and `col_idx` are 0-based and only used for error messages.
fn decode_cell(field_str: &str, row_idx: usize, col_idx: usize) -> SpassResult<String> {
    if field_str.is_empty() {
        return Ok(String::new());
    }

    let decoded = BASE64.decode(field_str).map_err(|e| {
        SpassError::Parsing(format!(
            "schema row {row_idx}: column {col_idx} Base64 decode failed: {e}"
        ))
    })?;

    if decoded.as_slice() == ABSENT_SENTINEL {
        return Ok(String::new());
    }

    String::from_utf8(decoded).map_err(|_| {
        SpassError::Parsing(format!(
            "schema row {row_idx}: column {col_idx} bytes are not valid UTF-8"
        ))
    })
}

/// Splits plaintext at the first `next_table` marker. Returns `(header,
/// data_lines)`; the iterator stops at the next `next_table` marker
/// (Samsung writes additional tables, e.g. secure notes, after the
/// credentials block).
fn split_sections(plaintext: &str) -> SpassResult<(&str, impl Iterator<Item = &str>)> {
    let after_marker = plaintext
        .split_once("next_table")
        .map(|(_, rest)| rest)
        .ok_or_else(|| {
            SpassError::Parsing("schema plaintext missing 'next_table' marker".to_string())
        })?;

    let mut lines = after_marker.trim_start_matches(['\r', '\n']).lines();
    let header = lines
        .next()
        .ok_or_else(|| SpassError::Parsing("schema plaintext missing header line".to_string()))?;

    let data_lines = lines.take_while(|line| line.trim() != "next_table");

    Ok((header, data_lines))
}

/// Resolved name -> column index for each of the 5 required columns,
/// plus the diagnostic columns collected along the way.
struct ColumnLookup {
    /// One index per [`REQUIRED_COLUMNS`] slot, in that order.
    indices: [usize; 5],
    max_required_index: usize,
    recognized_columns: Vec<String>,
    unknown_columns: Vec<String>,
}

/// What `ColumnLookup::from_header` populates when at least one required
/// column was absent. Carries the same diagnostic data the success path
/// uses, but skips the resolved indices because there's nothing to parse.
///
/// `_columns` suffix is load-bearing here; flowing into `BestEffortReport`'s
/// fields of the same name.
#[allow(clippy::struct_field_names)]
struct LookupFailure {
    recognized_columns: Vec<String>,
    missing_required_columns: Vec<String>,
    unknown_columns: Vec<String>,
}

impl ColumnLookup {
    fn from_header(header: &str) -> Result<Self, LookupFailure> {
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
            _ => Err(LookupFailure {
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

/// Default parser for the 35-column family. See the module docs for the
/// role split between the pipeline path and the registry path.
pub struct SchemaParser;

impl SchemaParser {
    /// Stateless; instantiate once and reuse.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Parses `plaintext`, resolving the 5 required columns by name.
    /// `sentinel` is the line-1 string captured upstream; it only flows
    /// into the returned [`BestEffortReport`] (and the error report) and
    /// doesn't affect parsing.
    ///
    /// An empty credentials table is not an error -- a valid export with
    /// zero saved passwords parses to an empty collection.
    ///
    /// # Errors
    ///
    /// - [`SpassError::Parsing`] if the plaintext has no `next_table`
    ///   marker, a row ends before the highest resolved column, or a
    ///   cell's wire shape is malformed (Base64, UTF-8).
    /// - [`SpassError::UnknownVersionUnparseable`] when at least one of
    ///   the 5 required columns is absent from the header -- carries the
    ///   diagnostic for the contribution flow.
    //
    // `&self` keeps call sites symmetric with the v30 parser and leaves
    // room for configuration without an API break.
    #[allow(clippy::unused_self)]
    pub fn parse_with_report(
        &self,
        sentinel: &str,
        plaintext: &[u8],
    ) -> SpassResult<(PasswordEntryCollection, BestEffortReport)> {
        let text = std::str::from_utf8(plaintext)
            .map_err(|_| SpassError::Parsing("Decrypted data is not valid UTF-8".to_string()))?;

        let (header, data_lines) = split_sections(text)?;

        let lookup = ColumnLookup::from_header(header).map_err(|failure| {
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
        // Rows average ~600 bytes on the wire (Base64 expands values ~33%);
        // a conservative pre-allocation.
        let mut collection = PasswordEntryCollection::with_capacity(text.len() / 600);

        for (row_idx, line) in data_lines.enumerate() {
            if line.is_empty() {
                continue;
            }

            let mut values: [String; 5] = Default::default();
            let mut resolved = 0usize;
            for (col_idx, cell) in line.split(';').enumerate() {
                if let Some(slot) = lookup.indices.iter().position(|&idx| idx == col_idx) {
                    values[slot] = decode_cell(cell, row_idx, col_idx)?;
                    resolved += 1;
                    if resolved == REQUIRED_COLUMNS.len() {
                        break;
                    }
                }
            }
            if resolved < REQUIRED_COLUMNS.len() {
                return Err(SpassError::Parsing(format!(
                    "schema row {row_idx} ends before column index {}; \
                     resolved {resolved} of {} required fields",
                    lookup.max_required_index,
                    REQUIRED_COLUMNS.len()
                )));
            }

            let [url, username, password, name, note] = values;
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

impl Default for SchemaParser {
    fn default() -> Self {
        Self::new()
    }
}

impl DataParser for SchemaParser {
    type Output<'a> = PasswordEntryCollection;

    const NAME: &'static str = "SPass 35-column schema parser";
    const FORMAT_ID: FormatId = FormatId::SpassCsvV31;

    fn can_parse(&self, data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }
        let Ok(text) = std::str::from_utf8(data) else {
            return false;
        };
        // The family's header starts with `_id;origin_url;` after the
        // `next_table` marker. Structurally distinct from v30's
        // `URL,Username,...`.
        text.split_once("next_table")
            .is_some_and(|(_, rest)| rest.contains("_id;origin_url;"))
    }

    fn parse<'a>(&'a self, data: &'a [u8]) -> SpassResult<Self::Output<'a>> {
        // The registry path has no upstream sentinel; read line 1 for the
        // diagnostics that ride error reports.
        let sentinel = std::str::from_utf8(data)
            .ok()
            .and_then(|t| t.lines().next())
            .map_or_else(|| "unknown".to_string(), |l| l.trim().to_string());
        self.parse_with_report(&sentinel, data)
            .map(|(collection, _)| collection)
    }

    fn schema(&self) -> ParserSchema {
        ParserSchema {
            format_name: "Samsung Pass CSV (35-column family)",
            file_extensions: &["csv"],
            mime_type: Some("text/csv"),
            binary_format: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(s: &str) -> String {
        BASE64.encode(s.as_bytes())
    }

    /// Builds a synthetic family-shape file with a custom sentinel and column
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
    fn parses_canonical_shape_with_unknown_sentinel() {
        let columns = canonical_columns();
        let bytes = make_file(
            "33",
            &columns,
            &[&[
                ("origin_url", "https://example.com"),
                ("username_value", "alice"),
                ("password_value", "secret"),
                ("title", "Example"),
                ("credential_memo", "my note"),
            ]],
        );

        let (entries, report) = SchemaParser::new().parse_with_report("33", &bytes).unwrap();
        assert_eq!(entries.len(), 1);
        let e = &entries.entries()[0];
        assert_eq!(e.url.as_str(), "https://example.com");
        assert_eq!(e.username.as_str(), "alice");
        assert_eq!(e.password.as_str(), "secret");
        assert_eq!(e.name.as_str(), "Example");
        assert_eq!(e.note.as_str(), "my note");

        assert_eq!(report.sentinel, "33");
        assert_eq!(report.entries_extracted, 1);
        assert!(report.missing_required_columns.is_empty());
        assert_eq!(report.recognized_columns.len(), 5);
    }

    #[test]
    fn survives_reordered_columns() {
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

        let (entries, _report) = SchemaParser::new().parse_with_report("32", &bytes).unwrap();
        let e = &entries.entries()[0];
        assert_eq!(e.url.as_str(), "https://x.com");
        assert_eq!(e.name.as_str(), "X");
        assert_eq!(e.password.as_str(), "hunter2");
    }

    #[test]
    fn tolerates_rows_longer_than_the_header() {
        let columns = canonical_columns();
        let header = columns.join(";");
        let mut bytes = format!("32\nfoo\nbar\nnext_table\n{header}\n");
        let mut parts: Vec<String> = columns.iter().map(|_| String::new()).collect();
        parts[1] = b64("https://long.example.com");
        parts[4] = b64("carol");
        parts[6] = b64("pw");
        parts[7] = b64("Long");
        parts[8] = b64("");
        bytes.push_str(&parts.join(";"));
        // Two extra trailing fields beyond the header width.
        bytes.push_str(";extra1;extra2\n");

        let (entries, _) = SchemaParser::new()
            .parse_with_report("32", bytes.as_bytes())
            .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries.entries()[0].username.as_str(), "carol");
    }

    #[test]
    fn empty_credentials_table_parses_to_zero_entries() {
        let bytes = make_file("31", &canonical_columns(), &[]);
        let (entries, report) = SchemaParser::new().parse_with_report("31", &bytes).unwrap();
        assert!(entries.is_empty());
        assert_eq!(report.entries_extracted, 0);
        assert!(report.missing_required_columns.is_empty());
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
        let bytes = make_file("31", &columns, &[]);

        let err = SchemaParser::new()
            .parse_with_report("31", &bytes)
            .unwrap_err();
        match err {
            SpassError::UnknownVersionUnparseable(report) => {
                assert_eq!(report.sentinel, "31");
                assert_eq!(report.missing_required_columns, vec!["password_value"]);
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
            "33",
            &columns,
            &[&[
                ("origin_url", "https://a.com"),
                ("username_value", "u"),
                ("password_value", "p"),
                ("title", "A"),
                ("credential_memo", "n"),
            ]],
        );

        let (_, report) = SchemaParser::new().parse_with_report("33", &bytes).unwrap();
        assert!(report
            .unknown_columns
            .contains(&"brand_new_column_a".to_string()));
        assert!(report
            .unknown_columns
            .contains(&"brand_new_column_b".to_string()));
    }

    #[test]
    fn no_next_table_marker_errors() {
        let bytes = b"33\nfoo\nbar\nbaz\n".to_vec();
        let err = SchemaParser::new()
            .parse_with_report("33", &bytes)
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("next_table"), "got: {msg}");
    }

    #[test]
    fn row_ending_before_last_required_column_errors() {
        let columns = canonical_columns();
        let header = columns.join(";");
        let mut bytes = format!("32\nfoo\nbar\nnext_table\n{header}\n");
        // Only 5 (validly encoded) fields when credential_memo sits at
        // index 8.
        let short_row: Vec<String> = (0..5).map(|_| b64("x")).collect();
        bytes.push_str(&short_row.join(";"));
        bytes.push('\n');

        let err = SchemaParser::new()
            .parse_with_report("32", bytes.as_bytes())
            .unwrap_err();
        assert!(err.to_string().contains("ends before column index"));
    }

    #[test]
    fn null_sentinel_and_empty_cells_decode_to_empty_string() {
        let columns = canonical_columns();
        let bytes = make_file(
            "31",
            &columns,
            &[&[
                ("origin_url", "https://e.com"),
                ("username_value", "alice"),
                ("password_value", "pw"),
                ("title", "E"),
                ("credential_memo", "&&&NULL&&&"),
            ]],
        );
        let (entries, _) = SchemaParser::new().parse_with_report("31", &bytes).unwrap();
        assert_eq!(entries.entries()[0].note.as_str(), "");
    }

    #[test]
    fn malformed_base64_in_a_kept_column_errors_with_position() {
        let columns = canonical_columns();
        let header = columns.join(";");
        let mut bytes = format!("31\nfoo\nbar\nnext_table\n{header}\n");
        let mut parts: Vec<String> = columns.iter().map(|_| String::new()).collect();
        parts[1] = "!!!not-base64!!!".to_string();
        bytes.push_str(&parts.join(";"));
        bytes.push('\n');

        let err = SchemaParser::new()
            .parse_with_report("31", bytes.as_bytes())
            .unwrap_err();
        assert!(err.to_string().contains("row 0"));
        assert!(err.to_string().contains("Base64"));
    }

    #[test]
    fn malformed_base64_in_an_ignored_column_is_never_touched() {
        let columns = canonical_columns();
        let header = columns.join(";");
        let mut bytes = format!("31\nfoo\nbar\nnext_table\n{header}\n");
        let mut parts: Vec<String> = columns.iter().map(|_| String::new()).collect();
        parts[0] = "!!!not-base64!!!".to_string(); // _id -- not projected
        parts[1] = b64("https://e.com");
        parts[4] = b64("u");
        parts[6] = b64("p");
        parts[7] = b64("T");
        parts[8] = b64("");
        bytes.push_str(&parts.join(";"));
        bytes.push('\n');

        let (entries, _) = SchemaParser::new()
            .parse_with_report("31", bytes.as_bytes())
            .unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn stops_at_second_next_table_marker() {
        let columns = canonical_columns();
        let mut bytes = make_file(
            "31",
            &columns,
            &[&[
                ("origin_url", "https://a.com"),
                ("username_value", "u"),
                ("password_value", "p"),
                ("title", "A"),
                ("credential_memo", ""),
            ]],
        );
        bytes.extend_from_slice(b"next_table\nnote_table_header\nnote_row\n");

        let (entries, report) = SchemaParser::new().parse_with_report("31", &bytes).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(report.entries_extracted, 1);
    }

    #[test]
    fn registry_facing_parse_reads_sentinel_from_line_one() {
        let columns = vec![
            "_id",
            "origin_url",
            "username_value",
            // no password_value -> lookup failure carries the sentinel
            "title",
            "credential_memo",
        ];
        let bytes = make_file("77", &columns, &[]);
        let err = SchemaParser::new().parse(&bytes).unwrap_err();
        match err {
            SpassError::UnknownVersionUnparseable(report) => {
                assert_eq!(report.sentinel, "77");
            }
            other => panic!("expected UnknownVersionUnparseable, got {other:?}"),
        }
    }

    #[test]
    fn can_parse_recognises_family_shape() {
        let p = SchemaParser::new();
        assert!(p.can_parse(b"31\nx\nnext_table\n_id;origin_url;rest\n"));
        assert!(!p.can_parse(b"URL,Username,Password,Name,Note\na,b,c,d,e"));
        assert!(!p.can_parse(b""));
    }
}
