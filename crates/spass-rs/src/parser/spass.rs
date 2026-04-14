//! Samsung Pass CSV parser implementation.

use csv::ReaderBuilder;
use std::io::Cursor;

use super::trait_def::{DataParser, FormatId, ParserSchema};
use crate::domain::{PasswordEntry, PasswordEntryCollection, SpassError, SpassResult};

/// Parser for Samsung Pass CSV format.
///
/// This parser handles the CSV format exported by Samsung Pass, which contains
/// password entries with the following fields:
/// - URL
/// - Username
/// - Password
/// - Name
/// - Note
///
/// # Format Specification
///
/// The CSV file must have a header row with these exact column names.
/// Each subsequent row represents a password entry.
///
/// # Examples
///
/// ```
/// use spass::parser::{DataParser, SpassCsvParser};
///
/// let parser = SpassCsvParser::new();
/// let csv_data = b"URL,Username,Password,Name,Note\n\
///                  https://example.com,user@test.com,secret123,Example,My note";
///
/// let result = parser.parse(csv_data);
/// assert!(result.is_ok());
/// let collection = result.unwrap();
/// assert_eq!(collection.len(), 1);
/// ```
#[derive(Default)]
pub struct SpassCsvParser;

impl SpassCsvParser {
    /// Creates a new `SPass` CSV parser.
    ///
    /// # Examples
    ///
    /// ```
    /// use spass::parser::SpassCsvParser;
    /// use spass::parser::DataParser;
    ///
    /// let parser = SpassCsvParser::new();
    /// assert_eq!(SpassCsvParser::NAME, "SPass CSV Parser");
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Validates that the CSV has the expected header format.
    ///
    /// # Arguments
    ///
    /// * `headers` - The header record from the CSV.
    ///
    /// # Errors
    ///
    /// Returns `SpassError::Parsing` if headers don't match expected format.
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

    /// Parses a single CSV record into a password entry.
    ///
    /// # Arguments
    ///
    /// * `record` - The CSV record to parse.
    /// * `line_number` - The line number for error reporting.
    ///
    /// # Errors
    ///
    /// Returns `SpassError::Parsing` if the record is invalid.
    fn parse_record(record: &csv::StringRecord, line_number: usize) -> SpassResult<PasswordEntry> {
        if record.len() < 5 {
            return Err(SpassError::Parsing(format!(
                "Line {}: expected 5 fields, found {}",
                line_number,
                record.len()
            )));
        }

        let fields: Vec<String> = record.iter().map(String::from).collect();
        PasswordEntry::from_raw_strings(&fields)
            .map_err(|e| SpassError::Parsing(format!("Line {line_number}: {e}")))
    }
}

impl DataParser for SpassCsvParser {
    type Output<'a> = PasswordEntryCollection;

    const NAME: &'static str = "SPass CSV Parser";
    const FORMAT_ID: FormatId = FormatId::SpassCsv;

    fn can_parse(&self, data: &[u8]) -> bool {
        // Quick heuristic: check if it looks like CSV with expected headers
        if data.is_empty() {
            return false;
        }

        // Try to read first line
        if let Ok(first_line) = std::str::from_utf8(data) {
            let first_line = first_line.lines().next().unwrap_or("");
            // Check if it contains the expected CSV headers
            first_line.contains("URL")
                && first_line.contains("Username")
                && first_line.contains("Password")
        } else {
            false
        }
    }

    fn parse<'a>(&'a self, data: &'a [u8]) -> SpassResult<Self::Output<'a>> {
        let cursor = Cursor::new(data);
        let mut reader = ReaderBuilder::new()
            .has_headers(true)
            .flexible(false) // Strict: all rows must have same number of fields
            .trim(csv::Trim::All)
            .from_reader(cursor);

        // Validate headers
        let headers = reader
            .headers()
            .map_err(|e| SpassError::Parsing(format!("Failed to read CSV headers: {e}")))?;
        Self::validate_headers(headers)?;

        // Parse all records
        let mut collection = PasswordEntryCollection::new();
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
            format_name: "Samsung Pass CSV",
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
        assert_eq!(SpassCsvParser::NAME, "SPass CSV Parser");
    }

    #[test]
    fn test_format_id() {
        assert_eq!(SpassCsvParser::FORMAT_ID, FormatId::SpassCsv);
    }

    #[test]
    fn test_can_parse_valid_csv() {
        let parser = SpassCsvParser::new();
        let data = b"URL,Username,Password,Name,Note\ntest,user,pass,Test,note";
        assert!(parser.can_parse(data));
    }

    #[test]
    fn test_can_parse_empty_data() {
        let parser = SpassCsvParser::new();
        assert!(!parser.can_parse(b""));
    }

    #[test]
    fn test_can_parse_invalid_data() {
        let parser = SpassCsvParser::new();
        let data = b"This is not CSV data";
        assert!(!parser.can_parse(data));
    }

    #[test]
    fn test_parse_valid_csv() {
        let parser = SpassCsvParser::new();
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
        let parser = SpassCsvParser::new();
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
        let parser = SpassCsvParser::new();
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
        let parser = SpassCsvParser::new();
        let data = b"URL,Username,Password,Name,Note\nonly,three,fields";

        let result = parser.parse(data);
        assert!(result.is_err());
        // CSV library returns record error for wrong field count
        assert!(result.unwrap_err().to_string().contains("CSV"));
    }

    #[test]
    fn test_schema() {
        let parser = SpassCsvParser::new();
        let schema = parser.schema();

        assert_eq!(schema.format_name, "Samsung Pass CSV");
        assert_eq!(schema.file_extensions, &["csv"]);
        assert_eq!(schema.mime_type, Some("text/csv"));
        assert!(!schema.binary_format);
    }

    #[test]
    fn test_parse_with_whitespace() {
        let parser = SpassCsvParser::new();
        let data = b"URL,Username,Password,Name,Note\n  https://example.com  ,  user  ,  pass  ,  Test  ,  note  ";

        let result = parser.parse(data);
        assert!(result.is_ok());

        let collection = result.unwrap();
        let entries: Vec<_> = collection.entries().iter().collect();

        // CSV reader trims whitespace
        assert_eq!(entries[0].url.as_str(), "https://example.com");
        assert_eq!(entries[0].username.as_str(), "user");
    }
}
