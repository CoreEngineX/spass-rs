//! Parser trait definition using Generic Associated Types (GATs).
//!
//! This module defines the core `DataParser` trait that enables zero-copy
//! parsing of different password manager export formats.

use crate::domain::SpassResult;

/// Format identifier for different password manager formats.
///
/// # Examples
///
/// ```
/// use spass::parser::FormatId;
///
/// let format = FormatId::SpassCsvV30;
/// assert_eq!(format.as_str(), "spass_csv_v30");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FormatId {
    /// Samsung Pass v30: 5-column comma-delimited CSV.
    SpassCsvV30,
    /// Samsung Pass v31: 35-column semicolon-delimited Base64-encoded CSV;
    /// collapsed to the 5-field `PasswordEntry` shape at the parser boundary.
    SpassCsvV31,
    /// Chrome CSV export format.
    ChromeCsv,
    /// `LastPass` CSV export format.
    LastPassCsv,
    /// `Bitwarden` JSON export format.
    BitwardenJson,
}

impl FormatId {
    /// Snake-case identifier used in error messages, logs, and
    /// `cargo test` filters. Stable across versions; safe to match
    /// on externally.
    ///
    /// ```
    /// use spass::parser::FormatId;
    /// assert_eq!(FormatId::SpassCsvV30.as_str(), "spass_csv_v30");
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SpassCsvV30 => "spass_csv_v30",
            Self::SpassCsvV31 => "spass_csv_v31",
            Self::ChromeCsv => "chrome_csv",
            Self::LastPassCsv => "lastpass_csv",
            Self::BitwardenJson => "bitwarden_json",
        }
    }
}

/// Metadata describing a parser's capabilities.
///
/// This struct provides information about what a parser can handle,
/// including file extensions and content type hints.
#[derive(Debug, Clone)]
pub struct ParserSchema {
    /// Human-readable name of the format.
    pub format_name: &'static str,
    /// Supported file extensions (without the dot).
    pub file_extensions: &'static [&'static str],
    /// MIME type if applicable.
    pub mime_type: Option<&'static str>,
    /// Whether this parser can handle binary data.
    pub binary_format: bool,
}

/// Parser trait for converting raw decrypted data into password entries.
///
/// This trait uses Generic Associated Types (GATs) to enable zero-copy parsing
/// for performance-critical scenarios while still supporting traditional owned
/// data for simpler use cases.
///
///
/// # Thread Safety
///
/// All parsers must be `Send + Sync` to allow concurrent parsing in
/// multi-threaded environments.
///
/// # Examples
///
/// ```
/// use spass::parser::{DataParser, FormatId, ParserSchema};
/// use spass::domain::{PasswordEntryCollection, SpassResult};
///
/// struct MyParser;
///
/// impl DataParser for MyParser {
///     type Output<'a> = PasswordEntryCollection;
///
///     const NAME: &'static str = "My Custom Parser";
///     const FORMAT_ID: FormatId = FormatId::SpassCsvV30;
///
///     fn can_parse(&self, data: &[u8]) -> bool {
///         // Simple heuristic check
///         !data.is_empty()
///     }
///
///     fn parse<'a>(&'a self, data: &'a [u8]) -> SpassResult<Self::Output<'a>> {
///         // Parse implementation
///         Ok(PasswordEntryCollection::default())
///     }
///
///     fn schema(&self) -> ParserSchema {
///         ParserSchema {
///             format_name: "My Format",
///             file_extensions: &["csv"],
///             mime_type: Some("text/csv"),
///             binary_format: false,
///         }
///     }
/// }
/// ```
pub trait DataParser: Send + Sync {
    /// The output type of `parse`. A GAT so implementations can
    /// borrow from `data` (zero-copy parsers) instead of always
    /// returning an owned value.
    type Output<'a>
    where
        Self: 'a;

    /// Human-readable parser name. Used in logs and error messages
    /// that need to identify which parser tripped.
    const NAME: &'static str;

    /// Stable identifier the registry and pipeline match on.
    const FORMAT_ID: FormatId;

    /// Quick heuristic check used by
    /// [`crate::parser::ParserRegistry::auto_detect`].
    /// Implementations should NOT fully parse -- a header / magic-
    /// bytes / first-line inspection is enough. Returning `true`
    /// here doesn't promise that `parse` will succeed; it just
    /// promises this parser is the right one to try.
    fn can_parse(&self, data: &[u8]) -> bool;

    /// Convert `data` into the parser's output (typically a
    /// [`PasswordEntryCollection`](crate::domain::PasswordEntryCollection)).
    ///
    /// # Errors
    ///
    /// `SpassError::Parsing` for any structural problem in the
    /// input: missing required columns, malformed CSV / Base64
    /// inside a row, mismatched format version, etc. The error
    /// message is intended to be surface-able to the user.
    fn parse<'a>(&'a self, data: &'a [u8]) -> SpassResult<Self::Output<'a>>;

    /// Capability metadata (display name, file extensions, MIME
    /// type, binary-vs-text). Used by tooling and the CLI's
    /// `info` command; the pipeline itself doesn't consult this.
    fn schema(&self) -> ParserSchema;
}
