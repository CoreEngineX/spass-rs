//! JSON exporter for decrypted entries.

use std::io::Write;

use serde::{Serialize, Serializer};

use super::chunk::Chunked;
use crate::domain::{SpassError, SpassResult};
use crate::entries::{EntryBuffer, EntryRef};

/// Writes an [`EntryBuffer`] as a pretty-printed JSON array.
///
/// Each object in the array has the keys `name`, `url`, `username`,
/// `password`, and `note`.
pub struct JsonExporter;

/// View type used only for serialisation -- keeps serde out of the domain.
#[derive(Serialize)]
struct EntryRecord<'a> {
    name: &'a str,
    url: &'a str,
    username: &'a str,
    password: &'a str,
    note: &'a str,
}

impl<'a> From<EntryRef<'a>> for EntryRecord<'a> {
    fn from(entry: EntryRef<'a>) -> Self {
        Self {
            name: entry.name,
            url: entry.url,
            username: entry.username,
            password: entry.password,
            note: entry.note,
        }
    }
}

/// Serialises the entries one at a time, so no second copy of them is built.
struct Records<'a>(&'a EntryBuffer);

impl Serialize for Records<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0.iter().map(EntryRecord::from))
    }
}

impl JsonExporter {
    /// Write `entries` as a pretty-printed JSON array into `writer`, then flush it. The output is
    /// a top-level array of objects with the keys `name`, `url`, `username`, `password`, `note`
    /// -- the same schema as [`CsvExporter`](super::CsvExporter), just in JSON form.
    ///
    /// # Errors
    ///
    /// - [`SpassError::Io`] if `writer` fails.
    /// - [`SpassError::Parsing`] if `serde_json` fails to serialise.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use spass::domain::EntryPassword;
    /// use spass::export::JsonExporter;
    /// use spass::pipeline::DecryptionPipeline;
    ///
    /// let password = EntryPassword::new("secret".to_string());
    /// let outcome = DecryptionPipeline::default().decrypt_file("passwords.spass", &password)?;
    /// JsonExporter::write(&mut std::fs::File::create("passwords.json")?, &outcome.entries)?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn write<W: Write>(writer: &mut W, entries: &EntryBuffer) -> SpassResult<()> {
        let mut out = Chunked::new(writer);
        serde_json::to_writer_pretty(&mut out, &Records(entries)).map_err(|error| {
            if error.is_io() {
                SpassError::Io(error.into())
            } else {
                SpassError::Parsing(error.to_string())
            }
        })?;
        Ok(out.finish()?)
    }
}
