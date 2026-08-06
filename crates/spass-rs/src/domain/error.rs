use std::fmt;

use super::version_status::BestEffortReport;

/// Result type alias for spass operations.
pub type SpassResult<T> = Result<T, SpassError>;

/// Errors produced by the spass decryption pipeline.
#[derive(Debug)]
#[non_exhaustive]
pub enum SpassError {
    /// I/O error.
    Io(std::io::Error),
    /// File format or data structure could not be parsed.
    Parsing(String),
    /// A cryptographic parameter or data invariant failed validation.
    Validation(String),
    /// Misconfiguration (e.g. wrong file extension, missing path).
    Config(String),
    /// CSV read/write error.
    Csv(csv::Error),
    /// Decryption failed.
    ///
    /// The message is intentionally vague — distinguishing wrong password from
    /// corrupted data leaks information useful for padding oracle attacks.
    Decryption(String),
    /// The schema parser
    /// couldn't resolve all 5 required columns by name -- so we have nothing
    /// usable to hand the caller. The report carries the header metadata so
    /// the consumer can still build a contribution URL for the user.
    ///
    /// Boxed so the `Err` arm of `SpassResult` stays small in the common
    /// (success) case -- the report is ~128 bytes.
    UnknownVersionUnparseable(Box<BestEffortReport>),
}

impl fmt::Display for SpassError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "I/O error: {err}"),
            Self::Parsing(err) => write!(f, "Parsing error: {err}"),
            Self::Validation(err) => write!(f, "Validation error: {err}"),
            Self::Config(err) => write!(f, "Configuration error: {err}"),
            Self::Csv(err) => write!(f, "CSV error: {err}"),
            Self::Decryption(err) => write!(f, "Decryption error: {err}"),
            Self::UnknownVersionUnparseable(report) => write!(
                f,
                "Unknown .spass version \"{}\"; missing required column(s): {}",
                report.sentinel,
                report.missing_required_columns.join(", ")
            ),
        }
    }
}

impl std::error::Error for SpassError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Csv(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for SpassError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<csv::Error> for SpassError {
    fn from(err: csv::Error) -> Self {
        Self::Csv(err)
    }
}
