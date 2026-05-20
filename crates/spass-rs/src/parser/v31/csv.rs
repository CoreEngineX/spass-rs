//! Samsung Pass v31 parser -- collapses Samsung's 35-column wire layout to the
//! 5-field `PasswordEntry` shape the rest of the workspace consumes.
//!
//! Field mapping:
//!
//! | `PasswordEntry` | v31 column        | Why this column                                   |
//! |-----------------|-------------------|---------------------------------------------------|
//! | `url`           | `origin_url`      | the actual URL or android:// URI                  |
//! | `username`      | `username_value`  | the typed username, NOT `username_element` (form field name) |
//! | `password`      | `password_value`  | the typed password, NOT `password_element`        |
//! | `name`          | `title`           | the display name typed in Samsung Pass            |
//! | `note`          | `credential_memo` | the user's note                                   |

use crate::domain::{PasswordEntry, PasswordEntryCollection, SpassError, SpassResult};
use crate::parser::trait_def::{DataParser, FormatId, ParserSchema};
use crate::parser::v31::tokenize::{split_v31_sections, tokenize_row};

/// Parser for Samsung Pass v31 CSV format, collapsed to the 5-field record.
///
/// v31 plaintext stores 35 columns per row but every workspace consumer
/// (CLI CSV export, web JSON, iOS UI) only uses 5 fields. The remaining 30
/// columns (favicon, timestamps, app metadata, etc.) are discarded at the
/// parser boundary; surfacing them is left to a future parser variant when a
/// concrete consumer materialises.
#[derive(Default)]
pub struct SpassCsvV31Parser;

impl SpassCsvV31Parser {
    /// Stateless; instantiate once per pipeline and reuse.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl DataParser for SpassCsvV31Parser {
    type Output<'a> = PasswordEntryCollection;

    const NAME: &'static str = "SPass CSV v31 Parser";
    const FORMAT_ID: FormatId = FormatId::SpassCsvV31;

    fn can_parse(&self, data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }
        let Ok(text) = std::str::from_utf8(data) else {
            return false;
        };
        // The v31 header starts with `_id;origin_url;` after the `next_table`
        // marker. This is structurally distinct from v30's `URL,Username,...`.
        text.split_once("next_table")
            .is_some_and(|(_, rest)| rest.contains("_id;origin_url;"))
    }

    fn parse<'a>(&'a self, data: &'a [u8]) -> SpassResult<Self::Output<'a>> {
        let text = std::str::from_utf8(data)
            .map_err(|_| SpassError::Parsing("Decrypted data is not valid UTF-8".to_string()))?;

        let (_header, data_lines) = split_v31_sections(text)?;

        // Pre-allocate at the row count we expect. Samsung's v31 rows average
        // ~600 bytes (Base64 expands the underlying values ~33%); start with a
        // conservative estimate.
        let estimated_rows = text.len() / 600;
        let mut collection = PasswordEntryCollection::with_capacity(estimated_rows);

        for (idx, line) in data_lines.enumerate() {
            // Allow a trailing empty line at end-of-file silently.
            if line.is_empty() {
                continue;
            }
            let row = tokenize_row(line, idx)?;

            collection.push(PasswordEntry::new(
                row.origin_url,
                row.username_value,
                row.password_value,
                row.title,
                row.credential_memo,
            ));
        }

        if collection.is_empty() {
            return Err(SpassError::Parsing(
                "No password entries found in CSV file".to_string(),
            ));
        }

        Ok(collection)
    }

    fn schema(&self) -> ParserSchema {
        ParserSchema {
            format_name: "Samsung Pass CSV v31",
            file_extensions: &["csv"],
            mime_type: Some("text/csv"),
            binary_format: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

    fn b64(s: &str) -> String {
        BASE64.encode(s.as_bytes())
    }

    fn build_v31_plaintext(rows: &[[(usize, &str); 5]]) -> String {
        let header_cols = [
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
        let header = header_cols.join(";");
        let mut out = format!("31\ntrue;false;false;false\nfalse\nnext_table\n{header}\n");
        for row_fields in rows {
            let mut parts: Vec<String> = (0..35).map(|_| String::new()).collect();
            for (i, v) in row_fields {
                parts[*i] = b64(v);
            }
            out.push_str(&parts.join(";"));
            out.push('\n');
        }
        out
    }

    #[test]
    fn parser_constants() {
        assert_eq!(SpassCsvV31Parser::NAME, "SPass CSV v31 Parser");
        assert_eq!(SpassCsvV31Parser::FORMAT_ID, FormatId::SpassCsvV31);
    }

    #[test]
    fn can_parse_recognises_v31_shape() {
        let p = SpassCsvV31Parser::new();
        let text = build_v31_plaintext(&[]);
        assert!(p.can_parse(text.as_bytes()));
    }

    #[test]
    fn can_parse_rejects_v30() {
        let p = SpassCsvV31Parser::new();
        let v30 = b"spass_export_v1\nfoo\nnext_table\nURL,Username,Password,Name,Note\n";
        assert!(!p.can_parse(v30));
    }

    #[test]
    fn parse_single_row_collapses_to_password_entry() {
        let parser = SpassCsvV31Parser::new();
        let text = build_v31_plaintext(&[[
            (1, "https://example.com"), // origin_url
            (4, "alice@example.com"),   // username_value
            (7, "secret123"),           // password_value
            (17, "Example Site"),       // title
            (31, "my note"),            // credential_memo
        ]]);
        let collection = parser.parse(text.as_bytes()).unwrap();
        assert_eq!(collection.len(), 1);
        let entry = &collection.entries()[0];
        assert_eq!(entry.url.as_str(), "https://example.com");
        assert_eq!(entry.username.as_str(), "alice@example.com");
        assert_eq!(entry.password.as_str(), "secret123");
        assert_eq!(entry.name.as_str(), "Example Site");
        assert_eq!(entry.note.as_str(), "my note");
    }

    #[test]
    fn null_sentinel_collapses_to_empty_string() {
        // username_value present, credential_memo is the absent sentinel.
        let parser = SpassCsvV31Parser::new();
        let absent = "&&&NULL&&&";
        let text = build_v31_plaintext(&[[
            (1, "https://x.com"),
            (4, "alice"),
            (7, "pw"),
            (17, "X"),
            (31, absent),
        ]]);
        let collection = parser.parse(text.as_bytes()).unwrap();
        let entry = &collection.entries()[0];
        assert_eq!(entry.note.as_str(), "");
    }

    #[test]
    fn parse_empty_v31_errors() {
        let parser = SpassCsvV31Parser::new();
        let text = build_v31_plaintext(&[]);
        let err = parser.parse(text.as_bytes()).unwrap_err();
        assert!(err.to_string().contains("No password entries"));
    }

    #[test]
    fn parse_two_rows_preserves_order() {
        let parser = SpassCsvV31Parser::new();
        let text = build_v31_plaintext(&[
            [
                (1, "https://a.com"),
                (4, "a"),
                (7, "p1"),
                (17, "A"),
                (31, "n1"),
            ],
            [
                (1, "https://b.com"),
                (4, "b"),
                (7, "p2"),
                (17, "B"),
                (31, "n2"),
            ],
        ]);
        let collection = parser.parse(text.as_bytes()).unwrap();
        assert_eq!(collection.len(), 2);
        assert_eq!(collection.entries()[0].url.as_str(), "https://a.com");
        assert_eq!(collection.entries()[1].url.as_str(), "https://b.com");
    }
}
