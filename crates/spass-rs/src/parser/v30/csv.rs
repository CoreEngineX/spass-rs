//! Samsung Pass v30 CSV parser implementation.

use csv::ReaderBuilder;
use std::io::Cursor;

use crate::domain::{PasswordEntry, PasswordEntryCollection, SpassError, SpassResult};
use crate::parser::trait_def::{DataParser, FormatId, ParserSchema};

/// Parser for Samsung Pass v30 CSV format.
///
/// v30 plaintext is a 5-column comma-delimited CSV with the header
/// `URL,Username,Password,Name,Note` and one row per credential. The CSV
/// section sits after a leading metadata block separated by the literal
/// `next_table` marker.
///
/// # Examples
///
/// ```
/// use spass::parser::{DataParser, SpassCsvV30Parser};
///
/// let parser = SpassCsvV30Parser::new();
/// let csv_data = b"URL,Username,Password,Name,Note\n\
///                  https://example.com,user@test.com,secret123,Example,My note";
///
/// let result = parser.parse(csv_data);
/// assert!(result.is_ok());
/// let collection = result.unwrap();
/// assert_eq!(collection.len(), 1);
/// ```
#[derive(Default)]
pub struct SpassCsvV30Parser;

impl SpassCsvV30Parser {
    /// Stateless; instantiate once per pipeline and reuse.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    fn validate_headers(headers: &csv::StringRecord) -> SpassResult<()> {
        const EXPECTED_HEADERS: [&str; 5] = ["URL", "Username", "Password", "Name", "Note"];

        if headers.len() < EXPECTED_HEADERS.len() {
            return Err(SpassError::Parsing(format!(
                "Invalid CSV header: expected {} columns, found {}",
                EXPECTED_HEADERS.len(),
                headers.len()
            )));
        }

        for (i, (expected, actual)) in EXPECTED_HEADERS.into_iter().zip(headers).enumerate() {
            if actual.trim() != expected {
                return Err(SpassError::Parsing(format!(
                    "Invalid CSV header: expected '{expected}' at column {i}, found '{actual}'"
                )));
            }
        }

        Ok(())
    }

    fn parse_record(record: &csv::StringRecord, line_number: usize) -> SpassResult<PasswordEntry> {
        if record.len() < 5 {
            return Err(SpassError::Parsing(format!(
                "Line {}: expected 5 fields, found {}",
                line_number,
                record.len()
            )));
        }

        // Read directly from the record instead of building an intermediate Vec<String> --
        // saves 5 extra String allocations per row (10M allocs avoided for 1M entries).
        Ok(PasswordEntry::new(
            record[0].to_owned(),
            record[1].to_owned(),
            record[2].to_owned(),
            record[3].to_owned(),
            record[4].to_owned(),
        ))
    }
}

impl DataParser for SpassCsvV30Parser {
    type Output<'a> = PasswordEntryCollection;

    const NAME: &'static str = "SPass CSV v30 Parser";
    const FORMAT_ID: FormatId = FormatId::SpassCsvV30;

    fn can_parse(&self, data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }
        let Ok(text) = std::str::from_utf8(data) else {
            return false;
        };
        // The CSV header may be on line 1 (bare CSV) or after the `next_table`
        // marker (full Samsung Pass plaintext format).
        text.lines().any(|line| {
            line.contains("URL") && line.contains("Username") && line.contains("Password")
        })
    }

    fn parse<'a>(&'a self, data: &'a [u8]) -> SpassResult<Self::Output<'a>> {
        let text = std::str::from_utf8(data)
            .map_err(|_| SpassError::Parsing("Decrypted data is not valid UTF-8".to_string()))?;

        // v30 plaintext has two sections separated by `next_table`. Skip
        // everything up to and including that marker so the CSV reader starts
        // at the `URL,Username,Password,Name,Note` header line.
        let csv_text = if let Some(after) = text.split_once("next_table") {
            after.1.trim_start_matches(['\r', '\n'])
        } else {
            text
        };

        let cursor = Cursor::new(csv_text.as_bytes());
        let mut reader = ReaderBuilder::new()
            .has_headers(true)
            .flexible(false)
            .trim(csv::Trim::All)
            .from_reader(cursor);

        let headers = reader
            .headers()
            .map_err(|e| SpassError::Parsing(format!("Failed to read CSV headers: {e}")))?;
        Self::validate_headers(headers)?;

        // Estimate row count to pre-allocate -- avoids ~20 doubling reallocations
        // for large files. 120 bytes/row is a conservative average.
        let estimated_rows = csv_text.len() / 120;
        let mut collection = PasswordEntryCollection::with_capacity(estimated_rows);
        for (idx, result) in reader.records().enumerate() {
            let record = result.map_err(|e| {
                SpassError::Parsing(format!(
                    "Failed to read CSV record at line {}: {e}",
                    idx + 2
                ))
            })?;

            collection.push(Self::parse_record(&record, idx + 2)?);
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
            format_name: "Samsung Pass CSV v30",
            file_extensions: &["csv"],
            mime_type: Some("text/csv"),
            binary_format: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parser_name() {
        assert_eq!(SpassCsvV30Parser::NAME, "SPass CSV v30 Parser");
    }

    #[test]
    fn test_format_id() {
        assert_eq!(SpassCsvV30Parser::FORMAT_ID, FormatId::SpassCsvV30);
    }

    #[test]
    fn test_can_parse_valid_csv() {
        let parser = SpassCsvV30Parser::new();
        let data = b"URL,Username,Password,Name,Note\ntest,user,pass,Test,note";
        assert!(parser.can_parse(data));
    }

    #[test]
    fn test_can_parse_empty_data() {
        let parser = SpassCsvV30Parser::new();
        assert!(!parser.can_parse(b""));
    }

    #[test]
    fn test_can_parse_invalid_data() {
        let parser = SpassCsvV30Parser::new();
        let data = b"This is not CSV data";
        assert!(!parser.can_parse(data));
    }

    #[test]
    fn test_parse_valid_csv() {
        let parser = SpassCsvV30Parser::new();
        let data = b"URL,Username,Password,Name,Note\n\
                     https://example.com,user@test.com,secret123,Example Site,My note here\n\
                     android://com.app,testuser,pass456,Android App,Another note";

        let result = parser.parse(data);
        assert!(result.is_ok());

        let collection = result.unwrap();
        assert_eq!(collection.len(), 2);

        let entries: Vec<_> = collection.entries().iter().collect();
        assert_eq!(entries[0].url.as_str(), "https://example.com");
        assert_eq!(entries[0].username.as_str(), "user@test.com");
        assert_eq!(entries[0].name.as_str(), "Example Site");

        assert_eq!(entries[1].url.as_str(), "android://com.app");
        assert_eq!(entries[1].username.as_str(), "testuser");
    }

    #[test]
    fn test_parse_empty_csv() {
        let parser = SpassCsvV30Parser::new();
        let data = b"URL,Username,Password,Name,Note\n";

        let result = parser.parse(data);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("No password entries found"));
    }

    #[test]
    fn test_parse_invalid_headers() {
        let parser = SpassCsvV30Parser::new();
        let data = b"Wrong,Headers,Here\ndata,data,data";

        let result = parser.parse(data);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid CSV header"));
    }

    #[test]
    fn test_parse_missing_fields() {
        let parser = SpassCsvV30Parser::new();
        let data = b"URL,Username,Password,Name,Note\nonly,three,fields";

        let result = parser.parse(data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("CSV"));
    }

    #[test]
    fn test_schema() {
        let parser = SpassCsvV30Parser::new();
        let schema = parser.schema();

        assert_eq!(schema.format_name, "Samsung Pass CSV v30");
        assert_eq!(schema.file_extensions, &["csv"]);
        assert_eq!(schema.mime_type, Some("text/csv"));
        assert!(!schema.binary_format);
    }

    #[test]
    fn test_parse_with_whitespace() {
        let parser = SpassCsvV30Parser::new();
        let data = b"URL,Username,Password,Name,Note\n  https://example.com  ,  user  ,  pass  ,  Test  ,  note  ";

        let result = parser.parse(data);
        assert!(result.is_ok());

        let collection = result.unwrap();
        let entries: Vec<_> = collection.entries().iter().collect();
        assert_eq!(entries[0].url.as_str(), "https://example.com");
        assert_eq!(entries[0].username.as_str(), "user");
    }
}
