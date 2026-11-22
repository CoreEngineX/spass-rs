//! Export formats for decrypted entries.
//!
//! Exporters serialise an [`EntryBuffer`] to a byte stream. Each exporter is gated behind a
//! feature flag so binary size is only paid for the formats actually used. Each buffers its
//! output in a zeroizing chunk of its own and writes it to the caller's writer as it fills.
//!
//! | Feature        | Type              |
//! |----------------|-------------------|
//! | `export-csv`   | [`CsvExporter`]   |
//! | `export-json`  | [`JsonExporter`]  |
//!
//! [`EntryBuffer`]: crate::EntryBuffer

#[cfg(any(feature = "export-csv", feature = "export-json"))]
mod chunk;

#[cfg(feature = "export-csv")]
mod csv;

#[cfg(feature = "export-json")]
mod json;

#[cfg(feature = "export-csv")]
pub use csv::CsvExporter;

#[cfg(feature = "export-json")]
pub use json::JsonExporter;
