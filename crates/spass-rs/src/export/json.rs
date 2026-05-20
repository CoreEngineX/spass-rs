//! JSON exporter for password entries.

use std::io::Write;

use crate::domain::{PasswordEntryCollection, SpassError, SpassResult};

/// Writes a [`PasswordEntryCollection`] as a pretty-printed JSON array.
///
/// Each object in the array has the keys `name`, `url`, `username`,
/// `password`, and `note`.
pub struct JsonExporter;

/// View type used only for serialisation — keeps serde out of the domain.
#[derive(serde::Serialize)]
struct EntryRecord<'a> {
    name: &'a str,
    url: &'a str,
    username: &'a str,
    password: &'a str,
    note: &'a str,
}

impl JsonExporter {
    /// Write `collection` as a pretty-printed JSON array into
    /// `writer`. The output is a top-level array of objects with
    /// the keys `name`, `url`, `username`, `password`, `note` --
    /// the same schema as [`CsvExporter`](super::CsvExporter), just
    /// in JSON form.
    ///
    /// # Errors
    ///
    /// [`SpassError::Parsing`] if `serde_json` fails to serialise
    /// (e.g. the writer rejects bytes mid-stream).
    ///
    /// # Examples
    ///
    /// Write to an in-memory buffer:
    ///
    /// ```
    /// use spass::domain::PasswordEntryCollection;
    /// use spass::export::JsonExporter;
    ///
    /// let collection = PasswordEntryCollection::new();
    /// let mut buf = Vec::new();
    /// JsonExporter::write(&mut buf, &collection).unwrap();
    ///
    /// let json = String::from_utf8(buf).unwrap();
    /// assert_eq!(json, "[]");
    /// ```
    pub fn write<W: Write>(
        writer: &mut W,
        collection: &PasswordEntryCollection,
    ) -> SpassResult<()> {
        let records: Vec<EntryRecord<'_>> = collection
            .iter()
            .map(|e| EntryRecord {
                name: e.name.as_str(),
                url: e.url.as_str(),
                username: e.username.as_str(),
                password: e.password.as_str(),
                note: e.note.as_str(),
            })
            .collect();

        serde_json::to_writer_pretty(writer, &records)
            .map_err(|e| SpassError::Parsing(e.to_string()))
    }
}
