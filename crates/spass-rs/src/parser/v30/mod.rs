//! Samsung Pass v30 plaintext format.
//!
//! v30 is the original 5-column comma-delimited CSV layout. See
//! `spass-docs/spass-core-api.md` §3.2 for the wire shape.

mod csv;

pub use csv::SpassCsvV30Parser;
