//! The v30 format: comma-delimited CSV with a header row, after a `next_table` line.

use csv::ReaderBuilder;
use std::io::Cursor;

use super::{OracleEntry, entry};
use crate::domain::{SpassError, SpassResult};

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

fn parse_record(record: &csv::StringRecord, line_number: usize) -> SpassResult<OracleEntry> {
    if record.len() < 5 {
        return Err(SpassError::Parsing(format!(
            "Line {}: expected 5 fields, found {}",
            line_number,
            record.len()
        )));
    }

    Ok(entry(
        record[0].to_owned(),
        record[1].to_owned(),
        record[2].to_owned(),
        record[3].to_owned(),
        record[4].to_owned(),
    ))
}

/// Parses v30 plaintext with the `csv` crate: a required header row, equal-width records and
/// every field trimmed.
///
/// # Errors
///
/// As [`oracle::decrypt`](super::decrypt) for a v30 plaintext.
pub fn parse_v30(data: &[u8]) -> SpassResult<Vec<OracleEntry>> {
    let text = std::str::from_utf8(data)
        .map_err(|_| SpassError::Parsing("Decrypted data is not valid UTF-8".to_string()))?;

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
    validate_headers(headers)?;

    let mut entries = Vec::with_capacity(csv_text.len() / 120);
    for (idx, result) in reader.records().enumerate() {
        let record = result.map_err(|e| {
            SpassError::Parsing(format!(
                "Failed to read CSV record at line {}: {e}",
                idx + 2
            ))
        })?;

        entries.push(parse_record(&record, idx + 2)?);
    }

    if entries.is_empty() {
        return Err(SpassError::Parsing(
            "No password entries found in CSV file".to_string(),
        ));
    }

    Ok(entries)
}
