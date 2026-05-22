//! Password entry parsers for different formats.
//!
//! This module provides parsing functionality for converting decrypted data
//! into structured password entries. Each Samsung Pass version lives in its
//! own `parser/vNN/` subdirectory; adding a new version is purely additive.
//!
//! `lenient` is the fallback path for files whose line-1 sentinel matches no
//! known version. It's invoked directly by the pipeline (not via the
//! [`ParserRegistry`]) because its API takes a sentinel string and returns
//! a [`crate::domain::BestEffortReport`] alongside the entries -- neither of
//! which fits the [`DataParser`] trait's signature.

mod lenient;
mod registry;
pub mod trait_def;
pub mod v30;
pub mod v31;

pub(crate) use lenient::LenientV31Parser;
pub use registry::ParserRegistry;
pub use trait_def::{DataParser, FormatId, ParserSchema};
pub use v30::SpassCsvV30Parser;
pub use v31::SpassCsvV31Parser;
