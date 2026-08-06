//! Password entry parsers for different formats.
//!
//! Two parsers total. `v30` handles the original comma-delimited plaintext
//! CSV. `schema` is the default parser for the 35-column semicolon + Base64
//! family (v31, v32, and every unknown sentinel): it resolves the projected
//! columns by name from the header, so a same-layout Samsung version bump
//! needs no parser changes at all.
//!
//! The pipeline calls [`SchemaParser::parse_with_report`] directly (its
//! sentinel-in, report-out signature doesn't fit the [`DataParser`] trait);
//! the trait impl serves the [`ParserRegistry`] tooling surface.

mod registry;
mod schema;
pub mod trait_def;
pub mod v30;

pub use registry::ParserRegistry;
pub use schema::SchemaParser;
pub use trait_def::{DataParser, FormatId, ParserSchema};
pub use v30::SpassCsvV30Parser;
