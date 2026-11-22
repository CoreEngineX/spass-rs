//! CSV exporter for decrypted entries.

use std::io::{self, Write};

use csv_core::{WriteResult, Writer};

use super::chunk::Chunked;
use crate::domain::SpassResult;
use crate::entries::EntryBuffer;

const HEADER: [&str; 5] = ["name", "url", "username", "password", "note"];

/// Writes an [`EntryBuffer`] as CSV.
///
/// The header is `name,url,username,password,note`. A field is quoted only where it holds a
/// comma, a quote or a line break; records end in `\n`. The output is byte for byte what the `csv`
/// crate's default writer produced.
pub struct CsvExporter;

impl CsvExporter {
    /// Write `entries` as CSV into `writer`, then flush it.
    ///
    /// # Errors
    ///
    /// [`SpassError::Io`](crate::SpassError::Io) if `writer` fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use spass::domain::EntryPassword;
    /// use spass::export::CsvExporter;
    /// use spass::pipeline::DecryptionPipeline;
    ///
    /// let password = EntryPassword::new("secret".to_string());
    /// let outcome = DecryptionPipeline::default().decrypt_file("passwords.spass", &password)?;
    /// CsvExporter::write(std::fs::File::create("passwords.csv")?, &outcome.entries)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn write<W: Write>(writer: W, entries: &EntryBuffer) -> SpassResult<()> {
        let mut out = Chunked::new(writer);
        let mut csv = Writer::new();

        write_record(&mut csv, &mut out, HEADER)?;
        for entry in entries {
            let record = [
                entry.name,
                entry.url,
                entry.username,
                entry.password,
                entry.note,
            ];
            write_record(&mut csv, &mut out, record)?;
        }
        Ok(out.finish()?)
    }
}

fn write_record<W: Write>(
    csv: &mut Writer,
    out: &mut Chunked<W>,
    fields: [&str; 5],
) -> io::Result<()> {
    for (index, field) in fields.into_iter().enumerate() {
        if index > 0 {
            loop {
                let (result, written) = csv.delimiter(out.spare());
                out.advance(written);
                match result {
                    WriteResult::InputEmpty => break,
                    WriteResult::OutputFull => out.drain()?,
                }
            }
        }
        let mut rest = field.as_bytes();
        loop {
            let (result, read, written) = csv.field(rest, out.spare());
            rest = &rest[read..];
            out.advance(written);
            match result {
                WriteResult::InputEmpty => break,
                WriteResult::OutputFull => out.drain()?,
            }
        }
    }
    loop {
        let (result, written) = csv.terminator(out.spare());
        out.advance(written);
        match result {
            WriteResult::InputEmpty => return Ok(()),
            WriteResult::OutputFull => out.drain()?,
        }
    }
}
