//! Password entry parsers for different formats.
//!
//! This module provides parsing functionality for converting decrypted data
//! into structured password entries. Each Samsung Pass version lives in its
//! own `parser/vNN/` subdirectory; adding a new version is purely additive.

mod registry;
pub mod trait_def;
pub mod v30;
pub mod v31;

pub use registry::ParserRegistry;
pub use trait_def::{DataParser, FormatId, ParserSchema};
pub use v30::SpassCsvV30Parser;
pub use v31::SpassCsvV31Parser;
