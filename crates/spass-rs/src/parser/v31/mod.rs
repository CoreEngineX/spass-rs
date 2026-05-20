//! Samsung Pass v31 plaintext format.
//!
//! v31 is the 35-column semicolon-delimited Base64-encoded layout. See
//! `spass-docs/spass-core-api.md` §3.3 - §3.5 for the wire shape and the
//! field-mapping table.
//!
//! `csv::SpassCsvV31Parser` collapses Samsung's 35 columns to the 5-field
//! `PasswordEntry` shape that the rest of the workspace already speaks.
//! `tokenize::tokenize_row` does the per-row split + Base64 of the 5 fields
//! we project + `&&&NULL&&&` sentinel mapping.

mod csv;
pub(crate) mod tokenize;

pub use csv::SpassCsvV31Parser;
