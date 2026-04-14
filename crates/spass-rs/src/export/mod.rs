//! Export formats for password entries.
//!
//! Exporters serialise a [`PasswordEntryCollection`] to a byte stream.
//! Each exporter is gated behind a feature flag so binary size is only paid
//! for the formats actually used.
//!
//! | Feature        | Type              |
//! |----------------|-------------------|
//! | `export-csv`   | [`CsvExporter`]   |
//! | `export-json`  | [`JsonExporter`]  |
//!
//! [`PasswordEntryCollection`]: crate::domain::PasswordEntryCollection

#[cfg(feature = "export-csv")]
mod csv;

#[cfg(feature = "export-json")]
mod json;

#[cfg(feature = "export-csv")]
pub use csv::CsvExporter;

#[cfg(feature = "export-json")]
pub use json::JsonExporter;
