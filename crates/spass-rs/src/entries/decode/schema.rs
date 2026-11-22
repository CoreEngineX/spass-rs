//! The 35-column family (v31, v32 and every unknown sentinel), decoded in place.
//!
//! Semicolon-delimited rows after a `next_table` line, each cell Base64-encoded, with `&&&NULL&&&`
//! for an absent value. The five kept columns are found by name in the header. Cells outside them
//! are walked past, never decoded.
//!
//! Each row's kept cells are decoded into a scratch buffer and written back from byte 0 of the
//! plaintext's own buffer once all five are read. A decoded cell is shorter than the text it came
//! from, so the write position never passes the row being read.

use std::ops::Range;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::{DecodeSliceError, Engine as _};
use memchr::{memchr, memchr_iter};
use zeroize::Zeroizing;

use super::{Ends, Plaintext, after_marker, not_utf8, replace_larger, seal, trimmed_span};
use crate::domain::{BestEffortReport, SpassError, SpassResult};
use crate::entries::buffer::{EntryBuffer, FIELDS};

/// What Samsung writes for an absent value, once Base64-decoded.
const ABSENT: &[u8] = b"&&&NULL&&&";

/// Header names of the kept columns, in slot order.
const REQUIRED_COLUMNS: [&str; FIELDS] = [
    "origin_url",
    "username_value",
    "password_value",
    "title",
    "credential_memo",
];

#[derive(Clone, Copy)]
enum Slot {
    Url,
    Username,
    Password,
    Name,
    Note,
}

impl Slot {
    const ALL: [Slot; FIELDS] = [
        Slot::Url,
        Slot::Username,
        Slot::Password,
        Slot::Name,
        Slot::Note,
    ];

    /// Position among the five kept fields; the order of [`Self::ALL`].
    fn index(self) -> usize {
        match self {
            Self::Url => 0,
            Self::Username => 1,
            Self::Password => 2,
            Self::Name => 3,
            Self::Note => 4,
        }
    }

    /// A password may legitimately start or end with whitespace.
    fn trims(self) -> bool {
        match self {
            Self::Password => false,
            Self::Url | Self::Username | Self::Name | Self::Note => true,
        }
    }
}

/// Decodes the entries of `plain` in place. `sentinel` is the line-1 string, kept for the report.
///
/// An empty credentials table is valid and yields no entries.
///
/// # Errors
///
/// - `SpassError::Parsing` if there is no `next_table` marker or header line, a row ends before
///   the last kept column, a kept cell is not Base64 or not UTF-8, or the header is not UTF-8.
/// - `SpassError::UnknownVersionUnparseable` if a kept column is missing from the header.
pub(crate) fn decode_schema(
    plain: Plaintext,
    sentinel: &str,
) -> SpassResult<(EntryBuffer, BestEffortReport)> {
    let Plaintext {
        mut bytes,
        start,
        len,
    } = plain;
    let end = start + len;

    let (header_line, columns, first_row) = {
        let text = &bytes[start..end];
        let header_at = after_marker(text).ok_or_else(|| {
            SpassError::Parsing("schema plaintext missing 'next_table' marker".to_string())
        })?;
        let header = next_line(text, header_at).ok_or_else(|| {
            SpassError::Parsing("schema plaintext missing header line".to_string())
        })?;
        let header_text =
            std::str::from_utf8(&text[header.start..header.end]).map_err(|_| not_utf8())?;
        let columns = Columns::from_header(header_text).map_err(|failure| {
            SpassError::UnknownVersionUnparseable(Box::new(BestEffortReport {
                sentinel: sentinel.to_owned(),
                header_line: header_text.to_owned(),
                recognized_columns: failure.recognized,
                missing_required_columns: failure.missing,
                unknown_columns: failure.unknown,
                entries_extracted: 0,
            }))
        })?;
        (header_text.to_owned(), columns, header.next)
    };

    // A row holds at least four `;` and a line break.
    let rows = &bytes[start + first_row..end];
    let max_rows = (memchr_iter(b'\n', rows).count() + 1).min(rows.len() / 5 + 1);
    let mut ends = Ends::with_entries(max_rows)?;
    let mut scratch = RowScratch::new();
    let mut write = 0;
    let mut line_start = first_row;
    let mut row = 0;
    loop {
        let (line, spans) = {
            let text = &bytes[start..end];
            let Some(line) = next_line(text, line_start) else {
                break;
            };
            let content = &text[line.start..line.end];
            if is_table_end(content) {
                break;
            }
            let spans = if content.is_empty() {
                None
            } else {
                Some(scratch.read_row(content, &columns, row)?)
            };
            (line, spans)
        };

        if let Some(spans) = spans {
            // Writing through the part before the next row turns an overrun into a bounds panic.
            let (written, _unread) = bytes.split_at_mut(start + line.next);
            for span in &spans {
                let field = scratch.field(span);
                written[write..write + field.len()].copy_from_slice(field);
                write += field.len();
                ends.push(write)?;
            }
        }
        line_start = line.next;
        row += 1;
    }

    let entries_extracted = ends.entries();
    drop(scratch);
    let buffer = seal(bytes, write, &ends)?;
    let report = BestEffortReport {
        sentinel: sentinel.to_owned(),
        header_line,
        recognized_columns: columns.recognized,
        missing_required_columns: Vec::new(),
        unknown_columns: columns.unknown,
        entries_extracted,
    };
    Ok((buffer, report))
}

/// One line of the plaintext, without its terminator: `str::lines` split on `\n`, one trailing
/// `\r` removed only where a `\n` followed it.
struct Line {
    start: usize,
    end: usize,
    next: usize,
}

fn next_line(text: &[u8], from: usize) -> Option<Line> {
    if from >= text.len() {
        return None;
    }
    let Some(newline) = memchr(b'\n', &text[from..]) else {
        return Some(Line {
            start: from,
            end: text.len(),
            next: text.len(),
        });
    };
    let newline = from + newline;
    let end = if newline > from && text[newline - 1] == b'\r' {
        newline - 1
    } else {
        newline
    };
    Some(Line {
        start: from,
        end,
        next: newline + 1,
    })
}

/// Whether `line`, trimmed of Unicode whitespace, is `next_table`. Rows start with a Base64
/// character or `;`, so the UTF-8 check runs only for a line that could be the marker.
fn is_table_end(line: &[u8]) -> bool {
    let first = line
        .iter()
        .copied()
        .find(|&byte| !matches!(byte, b' ' | b'\t' | b'\n' | 0x0B | 0x0C | b'\r'));
    matches!(first, Some(b'n' | 0x80..=0xFF))
        && std::str::from_utf8(line).is_ok_and(|text| text.trim() == "next_table")
}

/// Where each kept column sits in the header.
struct Columns {
    slot_by_column: Vec<Option<Slot>>,
    max_required_index: usize,
    recognized: Vec<String>,
    unknown: Vec<String>,
}

/// What the header held when a kept column was missing from it.
struct LookupFailure {
    recognized: Vec<String>,
    missing: Vec<String>,
    unknown: Vec<String>,
}

impl Columns {
    fn from_header(header: &str) -> Result<Self, LookupFailure> {
        let mut indices: [Option<usize>; FIELDS] = [None; FIELDS];
        let mut recognized = Vec::with_capacity(FIELDS);
        let mut unknown = Vec::new();

        for (index, name) in header.split(';').map(str::trim).enumerate() {
            if let Some(slot) = REQUIRED_COLUMNS.iter().position(|canon| *canon == name) {
                // The first of two columns with one name wins.
                if indices[slot].is_none() {
                    indices[slot] = Some(index);
                    recognized.push(REQUIRED_COLUMNS[slot].to_string());
                }
            } else {
                unknown.push(name.to_string());
            }
        }

        let [
            Some(origin_url),
            Some(username_value),
            Some(password_value),
            Some(title),
            Some(credential_memo),
        ] = indices
        else {
            let missing = REQUIRED_COLUMNS
                .iter()
                .zip(indices)
                .filter(|(_, index)| index.is_none())
                .map(|(name, _)| (*name).to_string())
                .collect();
            return Err(LookupFailure {
                recognized,
                missing,
                unknown,
            });
        };

        let resolved = [
            origin_url,
            username_value,
            password_value,
            title,
            credential_memo,
        ];
        let max_required_index = resolved.into_iter().max().unwrap_or(0);
        let mut slot_by_column = vec![None; max_required_index + 1];
        for (slot, index) in Slot::ALL.into_iter().zip(resolved) {
            slot_by_column[index] = Some(slot);
        }
        Ok(Self {
            slot_by_column,
            max_required_index,
            recognized,
            unknown,
        })
    }
}

/// Holds one row's decoded cells. Replaced, never grown, when a row needs more room.
struct RowScratch {
    bytes: Zeroizing<Vec<u8>>,
    used: usize,
}

impl RowScratch {
    const INITIAL_LEN: usize = 4096;

    fn new() -> Self {
        Self {
            bytes: Zeroizing::new(vec![0; Self::INITIAL_LEN]),
            used: 0,
        }
    }

    fn field(&self, span: &Range<usize>) -> &[u8] {
        &self.bytes[span.clone()]
    }

    /// Decodes the five kept cells of `line`, in column order, and returns where each landed in
    /// slot order.
    fn read_row(
        &mut self,
        line: &[u8],
        columns: &Columns,
        row: usize,
    ) -> SpassResult<[Range<usize>; FIELDS]> {
        self.used = 0;
        let mut spans: [Range<usize>; FIELDS] = std::array::from_fn(|_| 0..0);
        let mut resolved = 0;
        let mut cell_start = 0;
        let mut column = 0;
        while column < columns.slot_by_column.len() {
            let cell_end =
                memchr(b';', &line[cell_start..]).map_or(line.len(), |at| cell_start + at);
            if let Some(slot) = columns.slot_by_column[column] {
                spans[slot.index()] =
                    self.push_cell(&line[cell_start..cell_end], slot, row, column)?;
                resolved += 1;
                if resolved == FIELDS {
                    return Ok(spans);
                }
            }
            if cell_end == line.len() {
                break;
            }
            cell_start = cell_end + 1;
            column += 1;
        }
        Err(SpassError::Parsing(format!(
            "schema row {row} ends before column index {}; resolved {resolved} of {FIELDS} required fields",
            columns.max_required_index
        )))
    }

    fn push_cell(
        &mut self,
        cell: &[u8],
        slot: Slot,
        row: usize,
        column: usize,
    ) -> SpassResult<Range<usize>> {
        let start = self.used;
        if cell.is_empty() {
            return Ok(start..start);
        }

        let room = base64::decoded_len_estimate(cell.len());
        if self.bytes.len() - start < room {
            let len = (start + room).max(self.bytes.len() * 2);
            replace_larger(&mut self.bytes, len, start);
        }
        let decoded_len = BASE64
            .decode_slice(cell, &mut self.bytes[start..])
            .map_err(|error| {
                let reason = match error {
                    DecodeSliceError::DecodeError(error) => error.to_string(),
                    DecodeSliceError::OutputSliceTooSmall => "output slice too small".to_string(),
                };
                SpassError::Parsing(format!(
                    "schema row {row}: column {column} Base64 decode failed: {reason}"
                ))
            })?;

        let decoded = &self.bytes[start..start + decoded_len];
        if decoded == ABSENT {
            return Ok(start..start);
        }
        let text = std::str::from_utf8(decoded).map_err(|_| {
            SpassError::Parsing(format!(
                "schema row {row}: column {column} bytes are not valid UTF-8"
            ))
        })?;
        let span = if slot.trims() {
            let kept = trimmed_span(text);
            start + kept.start..start + kept.end
        } else {
            start..start + decoded_len
        };
        self.used = start + decoded_len;
        Ok(span)
    }
}
