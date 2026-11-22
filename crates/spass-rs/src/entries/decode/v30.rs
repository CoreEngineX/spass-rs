//! v30: comma-delimited CSV with a header row, unescaped by `csv-core` into a second buffer.
//!
//! The CSV is read the way the `csv` crate's default reader would read it with a required header
//! row, equal-width records and `Trim::All`: `\n`, `\r` and `\r\n` end a record, empty lines are
//! skipped, and every field is trimmed of Unicode whitespace.
//!
//! `csv-core` writes each record's unescaped fields to the second buffer at the write position.
//! The first five are trimmed, validated as UTF-8 and moved down to it; the rest are overwritten
//! by the next record. The plaintext buffer is zeroed and freed before the entries are handed back.

use csv_core::{ReadRecordResult, Reader, ReaderBuilder};
use memchr::memchr_iter;
use zeroize::Zeroizing;

use super::{Ends, Plaintext, after_marker, not_utf8, seal, too_large, trimmed_span};
use crate::domain::{SpassError, SpassResult};
use crate::entries::buffer::{EntryBuffer, FIELDS, INDEX_ENTRY_LEN};

const EXPECTED_HEADERS: [&str; FIELDS] = ["URL", "Username", "Password", "Name", "Note"];

/// Room for the zero padding before the index.
const PADDING_LEN: usize = 3;

/// Decodes the entries of `plain` into a second buffer and zeroes `plain`.
///
/// # Errors
///
/// `SpassError::Parsing` if the header is not `URL,Username,Password,Name,Note` (more columns may
/// follow), a record has another width than the header, a kept field is not UTF-8, or there are no
/// records.
pub(crate) fn decode_v30(plain: Plaintext) -> SpassResult<EntryBuffer> {
    let Plaintext { bytes, start, len } = plain;
    let text = &bytes[start..start + len];
    let table = &text[after_marker(text).unwrap_or(0)..];

    let max_records = record_bound(table);
    let capacity = INDEX_ENTRY_LEN
        .checked_mul(max_records)
        .and_then(|index_len| index_len.checked_add(table.len()))
        .and_then(|fields_and_index| fields_and_index.checked_add(PADDING_LEN))
        .ok_or_else(too_large)?;
    let mut out = Zeroizing::new(vec![0u8; capacity]);
    let mut ends = Ends::with_entries(max_records)?;
    let mut records = Records::new(table);

    let header_fields = match records.read(&mut out)? {
        Some(header) => {
            check_header(&out, records.field_ends(header))?;
            header.fields
        }
        None => {
            check_header(&out, &[])?;
            0
        }
    };

    let mut write = 0;
    let mut rows = 0;
    while let Some(record) = records.read(&mut out[write..])? {
        if record.fields != header_fields {
            return Err(unequal_fields(rows, record, header_fields));
        }
        write = keep_fields(&mut out, write, records.field_ends(record), &mut ends)?;
        rows += 1;
    }
    if ends.entries() == 0 {
        return Err(SpassError::Parsing(
            "No password entries found in CSV file".to_string(),
        ));
    }

    drop(bytes);
    seal(out, write, &ends)
}

/// The most records `table` can hold: one per line break, and one for a last line without one.
fn record_bound(table: &[u8]) -> usize {
    let line_feeds = memchr_iter(b'\n', table).count();
    let bare_returns = memchr_iter(b'\r', table)
        .filter(|&at| table.get(at + 1) != Some(&b'\n'))
        .count();
    line_feeds + bare_returns + 1
}

/// Checks the header record `ends` describes at the start of `out`.
fn check_header(out: &[u8], ends: &[usize]) -> SpassResult<()> {
    let mut names = [""; FIELDS];
    let mut start = 0;
    for (index, &end) in ends.iter().enumerate() {
        let name = std::str::from_utf8(&out[start..end])
            .map_err(|_| not_utf8())?
            .trim();
        if let Some(slot) = names.get_mut(index) {
            *slot = name;
        }
        start = end;
    }

    if ends.len() < FIELDS {
        return Err(SpassError::Parsing(format!(
            "Invalid CSV header: expected {FIELDS} columns, found {}",
            ends.len()
        )));
    }
    for (index, (expected, actual)) in EXPECTED_HEADERS.into_iter().zip(names).enumerate() {
        if actual != expected {
            return Err(SpassError::Parsing(format!(
                "Invalid CSV header: expected '{expected}' at column {index}, found '{actual}'"
            )));
        }
    }
    Ok(())
}

/// Moves the first five fields of the record at `base` in `out`, trimmed and checked as UTF-8,
/// down to `base`, records their end offsets, and returns where the next record's output starts.
fn keep_fields(out: &mut [u8], base: usize, ends: &[usize], kept: &mut Ends) -> SpassResult<usize> {
    let mut write = base;
    let mut field_start = base;
    for &end in ends.iter().take(FIELDS) {
        let field_end = base + end;
        let text = std::str::from_utf8(&out[field_start..field_end]).map_err(|_| not_utf8())?;
        let trimmed = trimmed_span(text);
        let source = field_start + trimmed.start..field_start + trimmed.end;
        let len = source.len();
        out.copy_within(source, write);
        write += len;
        kept.push(write)?;
        field_start = field_end;
    }
    Ok(write)
}

/// The error for a record of another width than the header, worded as the oracle's `csv` reader
/// words it. `row` counts the records after the header.
fn unequal_fields(row: usize, record: Record, expected: usize) -> SpassError {
    SpassError::Parsing(format!(
        "Failed to read CSV record at line {}: CSV error: record {} (line: {}, byte: {}): \
         found record with {} fields, but the previous record has {expected} fields",
        row + 2,
        record.at.record,
        record.at.line,
        record.at.byte,
        record.fields,
    ))
}

/// Where a record starts, as the `csv` crate counts: bytes consumed, lines, records already read.
#[derive(Clone, Copy)]
struct Position {
    byte: usize,
    line: u64,
    record: u64,
}

/// A record `csv-core` has written to the output buffer: its field count, and where it started.
#[derive(Clone, Copy)]
struct Record {
    fields: usize,
    at: Position,
}

struct Records<'a> {
    core: Reader,
    input: &'a [u8],
    at: Position,
    ends: Vec<usize>,
}

impl<'a> Records<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self {
            core: ReaderBuilder::new().build(),
            input,
            at: Position {
                byte: 0,
                line: 1,
                record: 0,
            },
            ends: vec![0; 8],
        }
    }

    /// End offsets of `record`'s fields in the output, until the next `read`.
    fn field_ends(&self, record: Record) -> &[usize] {
        &self.ends[..record.fields]
    }

    /// Reads the next record, unescaped, to the start of `out`. `None` at the end of the input.
    fn read(&mut self, out: &mut [u8]) -> SpassResult<Option<Record>> {
        let begin = self.at;
        let mut written = 0;
        let mut ends_written = 0;
        loop {
            let (result, consumed, output, field_ends) = self.core.read_record(
                &self.input[self.at.byte..],
                &mut out[written..],
                &mut self.ends[ends_written..],
            );
            self.at.byte += consumed;
            self.at.line = self.core.line();
            written += output;
            ends_written += field_ends;
            match result {
                ReadRecordResult::InputEmpty => {}
                ReadRecordResult::OutputFull => {
                    return Err(SpassError::Parsing(
                        "CSV record is larger than the plaintext".to_string(),
                    ));
                }
                ReadRecordResult::OutputEndsFull => {
                    let len = self.ends.len();
                    self.ends.resize(len * 2, 0);
                }
                ReadRecordResult::Record => {
                    self.at.record += 1;
                    return Ok(Some(Record {
                        fields: ends_written,
                        at: begin,
                    }));
                }
                ReadRecordResult::End => return Ok(None),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_bytes(text: &[u8]) -> SpassResult<Vec<[String; FIELDS]>> {
        let plain = Plaintext::new(Zeroizing::new(text.to_vec()), 0, text.len());
        decode_v30(plain).map(|buffer| {
            buffer
                .iter()
                .map(|e| [e.url, e.username, e.password, e.name, e.note].map(str::to_owned))
                .collect()
        })
    }

    #[test]
    fn quoted_fields_are_unescaped_and_trimmed() {
        let text = "x\nnext_table\nURL,Username,Password,Name,Note\n\
                    \" a,b \",u,\"p\"\"q\",\"two\nlines\", n \n";

        let entries = decode_bytes(text.as_bytes()).unwrap();

        assert_eq!(entries, [["a,b", "u", "p\"q", "two\nlines", "n"]]);
    }

    #[test]
    fn a_wrong_width_record_is_reported_with_its_position() {
        let text = b"next_table\nURL,Username,Password,Name,Note\na,b,c,d,e\n\nf,g,h\n";

        let error = decode_bytes(text).unwrap_err().to_string();

        assert!(
            error.starts_with(
                "Parsing error: Failed to read CSV record at line 3: CSV error: record 2 (line: "
            ),
            "{error}"
        );
        assert!(
            error.ends_with("found record with 3 fields, but the previous record has 5 fields"),
            "{error}"
        );
    }

    #[test]
    fn a_header_without_rows_is_an_error() {
        let error = decode_bytes(b"next_table\nURL,Username,Password,Name,Note\n").unwrap_err();

        assert!(error.to_string().contains("No password entries found"));
    }

    #[test]
    fn a_dropped_column_is_not_checked_as_utf8() {
        let text = b"next_table\nURL,Username,Password,Name,Note,Extra\na,b,c,d,e,\xff\n";

        assert_eq!(decode_bytes(text).unwrap().len(), 1);
    }

    #[test]
    fn a_kept_field_must_be_utf8() {
        let text = b"next_table\nURL,Username,Password,Name,Note\na,b,\xff,d,e\n";

        assert!(matches!(decode_bytes(text), Err(SpassError::Parsing(_))));
    }
}
