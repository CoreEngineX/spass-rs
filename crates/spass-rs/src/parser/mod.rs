//! Password entry parsers for different formats.
//!
//! This module provides parsing functionality for converting decrypted data
//! into structured password entries. It supports multiple formats through
//! a pluggable parser system.

mod registry;
mod spass;
mod trait_def;

pub use registry::ParserRegistry;
pub use spass::SpassCsvParser;
pub use trait_def::{DataParser, FormatId, ParserSchema};
