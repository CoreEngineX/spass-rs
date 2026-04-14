//! CSV exporter for password entries.

use std::io::Write;

use crate::domain::{PasswordEntryCollection, SpassError, SpassResult};

/// Writes a [`PasswordEntryCollection`] as RFC 4180-compliant CSV.
///
/// The output uses the header `name,url,username,password,note`.
/// All field quoting and escaping is handled by the `csv` crate.
pub struct CsvExporter;

impl CsvExporter {
    /// Write `collection` as CSV into `writer`.
    ///
    /// # Errors
    ///
    /// Returns [`SpassError::Csv`] on serialisation failure or
    /// [`SpassError::Io`] if flushing the writer fails.
    pub fn write<W: Write>(writer: W, collection: &PasswordEntryCollection) -> SpassResult<()> {
        let mut wtr = ::csv::Writer::from_writer(writer);

        wtr.write_record(["name", "url", "username", "password", "note"])
            .map_err(SpassError::Csv)?;

        for entry in collection {
            wtr.write_record([
                entry.name.as_str(),
                entry.url.as_str(),
                entry.username.as_str(),
                entry.password.as_str(),
                entry.note.as_str(),
            ])
            .map_err(SpassError::Csv)?;
        }

        wtr.flush().map_err(SpassError::Io)?;
        Ok(())
    }
}
