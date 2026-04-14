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
    /// Write `collection` as a pretty-printed JSON array into `writer`.
    ///
    /// # Errors
    ///
    /// Returns [`SpassError::Parsing`] if JSON serialisation fails.
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
