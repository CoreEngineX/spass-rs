//! The 35-column family: semicolon-delimited rows after a `next_table` line, each cell
//! Base64-encoded, with `&&&NULL&&&` for an absent value. The five kept columns are resolved by
//! name from the header; cells outside them are never decoded.

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};

use super::{OracleEntry, entry};
use crate::domain::{BestEffortReport, SpassError, SpassResult};

/// Header names of the kept columns, in the order `entry` takes its arguments.
const REQUIRED_COLUMNS: [&str; 5] = [
    "origin_url",
    "username_value",
    "password_value",
    "title",
    "credential_memo",
];

/// What Samsung writes for an absent value, once Base64-decoded.
const ABSENT_SENTINEL: &[u8] = b"&&&NULL&&&";

/// Decodes one cell. Empty input and the absent-sentinel both collapse to the empty string;
/// anything else is Base64-decoded and UTF-8-validated. `row_idx` and `col_idx` are 0-based and
/// only used for error messages.
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

/// Splits plaintext at the first `next_table` marker. Returns `(header, data_lines)`; the
/// iterator stops at the next `next_table` marker.
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

struct ColumnLookup {
    indices: [usize; 5],
    max_required_index: usize,
    recognized_columns: Vec<String>,
    unknown_columns: Vec<String>,
}

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
                if indices[slot].is_none() {
                    indices[slot] = Some(i);
                    recognized.push(REQUIRED_COLUMNS[slot].to_string());
                }
            } else {
                unknown.push(name.to_string());
            }
        }

        match indices {
            [
                Some(origin_url),
                Some(username_value),
                Some(password_value),
                Some(title),
                Some(credential_memo),
            ] => {
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
                    .filter(|(_, idx)| idx.is_none())
                    .map(|(name, _)| (*name).to_string())
                    .collect(),
                recognized_columns: recognized,
                unknown_columns: unknown,
            }),
        }
    }
}

/// Parses `plaintext`, resolving the five kept columns by name. `sentinel` is the line-1 string;
/// it only flows into the returned report.
///
/// # Errors
///
/// As [`oracle::decrypt`](super::decrypt) for a 35-column plaintext.
pub fn parse_schema(
    sentinel: &str,
    plaintext: &[u8],
) -> SpassResult<(Vec<OracleEntry>, BestEffortReport)> {
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
    let mut entries = Vec::with_capacity(text.len() / 600);

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
        entries.push(entry(url, username, password, name, note));
    }

    let report = BestEffortReport {
        sentinel: sentinel.to_string(),
        header_line: header_owned,
        recognized_columns: lookup.recognized_columns,
        missing_required_columns: Vec::new(),
        unknown_columns: lookup.unknown_columns,
        entries_extracted: entries.len(),
    };

    Ok((entries, report))
}
