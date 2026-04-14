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
/// let format = FormatId::SpassCsv;
/// assert_eq!(format.as_str(), "spass_csv");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FormatId {
    /// Samsung Pass CSV format (default).
    SpassCsv,
    /// Chrome CSV export format.
    ChromeCsv,
    /// `LastPass` CSV export format.
    LastPassCsv,
    /// `Bitwarden` JSON export format.
    BitwardenJson,
}

impl FormatId {
    /// Returns the format identifier as a string.
    ///
    /// # Examples
    ///
    /// ```
    /// use spass::parser::FormatId;
    ///
    /// let format = FormatId::SpassCsv;
    /// assert_eq!(format.as_str(), "spass_csv");
    /// ```
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SpassCsv => "spass_csv",
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
///     const FORMAT_ID: FormatId = FormatId::SpassCsv;
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
    /// The output type of the parser.
    type Output<'a>
    where
        Self: 'a;

    /// The human-readable name of this parser.
    ///
    /// # Examples
    ///
    /// ```
    /// use spass::parser::DataParser;
    /// # use spass::parser::SpassCsvParser;
    ///
    /// assert_eq!(SpassCsvParser::NAME, "SPass CSV Parser");
    /// ```
    const NAME: &'static str;

    /// The format identifier for this parser.
    ///
    /// # Examples
    ///
    /// ```
    /// use spass::parser::{DataParser, FormatId};
    /// # use spass::parser::SpassCsvParser;
    ///
    /// assert_eq!(SpassCsvParser::FORMAT_ID, FormatId::SpassCsv);
    /// ```
    const FORMAT_ID: FormatId;

    /// Checks if this parser can handle the given data.
    ///
    /// This method performs a quick heuristic check without fully parsing
    /// the data. It's used for auto-detection of formats.
    ///
    /// # Arguments
    ///
    /// * `data` - The raw data to check.
    ///
    /// # Examples
    ///
    /// ```
    /// use spass::parser::DataParser;
    /// # use spass::parser::SpassCsvParser;
    ///
    /// let parser = SpassCsvParser::new();
    /// let csv_data = b"URL,Username,Password,Name,Note\n";
    /// assert!(parser.can_parse(csv_data));
    /// ```
    fn can_parse(&self, data: &[u8]) -> bool;

    /// Parses the given data into password entries.
    ///
    /// # Arguments
    ///
    /// * `data` - The raw decrypted data to parse.
    ///
    /// # Returns
    ///
    /// Returns the parsed output on success.
    ///
    /// # Errors
    ///
    /// Returns `SpassError::Parsing` if:
    /// - The data format is invalid
    /// - Required fields are missing
    /// - Data is corrupted
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use spass::parser::DataParser;
    /// # use spass::parser::SpassCsvParser;
    ///
    /// let parser = SpassCsvParser::new();
    /// let data = b"URL,Username,Password,Name,Note\ntest,user,pass,Test,note";
    /// let result = parser.parse(data);
    /// assert!(result.is_ok());
    /// ```
    fn parse<'a>(&'a self, data: &'a [u8]) -> SpassResult<Self::Output<'a>>;

    /// Returns metadata about this parser's capabilities.
    ///
    /// # Examples
    ///
    /// ```
    /// use spass::parser::DataParser;
    /// # use spass::parser::SpassCsvParser;
    ///
    /// let parser = SpassCsvParser::new();
    /// let schema = parser.schema();
    /// assert_eq!(schema.format_name, "Samsung Pass CSV");
    /// ```
    fn schema(&self) -> ParserSchema;
}
