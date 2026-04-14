//! Parser registry for managing and auto-detecting parsers.

use std::collections::HashMap;

use super::spass::SpassCsvParser;
use super::trait_def::{DataParser, FormatId};
use crate::domain::{PasswordEntryCollection, SpassResult};

/// Parser function signature.
type ParseFn = Box<dyn Fn(&[u8]) -> SpassResult<PasswordEntryCollection> + Send + Sync>;

/// Can-parse function signature.
type CanParseFn = Box<dyn Fn(&[u8]) -> bool + Send + Sync>;

/// Registry for managing password format parsers.
///
/// This struct maintains a collection of registered parsers and provides
/// functionality for auto-detecting the appropriate parser for a given data set.
///
/// # Implementation Note
///
/// Due to GATs (Generic Associated Types) not being dyn-compatible, this registry
/// uses boxed closures rather than trait objects. This is a known limitation
/// that may be resolved in future Rust versions.
///
/// # Examples
///
/// ```
/// use spass::parser::{ParserRegistry, FormatId};
///
/// let registry = ParserRegistry::new();
/// assert!(registry.has_parser(FormatId::SpassCsv));
///
/// let csv_data = b"URL,Username,Password,Name,Note\ntest,user,pass,Test,note";
/// let detected = registry.auto_detect(csv_data);
/// assert_eq!(detected, Some(FormatId::SpassCsv));
/// ```
pub struct ParserRegistry {
    parsers: HashMap<FormatId, (ParseFn, CanParseFn, &'static str)>,
}

impl ParserRegistry {
    /// Creates a new parser registry with default parsers registered.
    ///
    /// By default, the following parsers are registered:
    /// - `SpassCsvParser` for Samsung Pass CSV format
    ///
    /// # Examples
    ///
    /// ```
    /// use spass::parser::ParserRegistry;
    ///
    /// let registry = ParserRegistry::new();
    /// // SpassCsvParser is automatically registered
    /// ```
    #[must_use]
    pub fn new() -> Self {
        let mut registry = Self {
            parsers: HashMap::new(),
        };

        // Register SpassCsvParser
        registry.parsers.insert(
            SpassCsvParser::FORMAT_ID,
            (
                Box::new(|data| SpassCsvParser::new().parse(data)),
                Box::new(|data| SpassCsvParser::new().can_parse(data)),
                SpassCsvParser::NAME,
            ),
        );

        registry
    }

    /// Parses data using the specified format.
    ///
    /// # Arguments
    ///
    /// * `id` - The format identifier.
    /// * `data` - The data to parse.
    ///
    /// # Returns
    ///
    /// Returns a `PasswordEntryCollection` on success.
    ///
    /// # Errors
    ///
    /// Returns `SpassError::Parsing` if no parser is registered for the format
    /// or if parsing fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use spass::parser::{ParserRegistry, FormatId};
    ///
    /// let registry = ParserRegistry::new();
    /// let csv_data = b"URL,Username,Password,Name,Note\ntest,user,pass,Test,note";
    /// let result = registry.parse(FormatId::SpassCsv, csv_data);
    /// assert!(result.is_ok());
    /// ```
    pub fn parse(&self, id: FormatId, data: &[u8]) -> SpassResult<PasswordEntryCollection> {
        if let Some((parse_fn, _, _)) = self.parsers.get(&id) {
            parse_fn(data)
        } else {
            Err(crate::domain::SpassError::Parsing(format!(
                "No parser registered for format: {}",
                id.as_str()
            )))
        }
    }

    /// Checks if a parser is registered for the given format.
    ///
    /// # Examples
    ///
    /// ```
    /// use spass::parser::{ParserRegistry, FormatId};
    ///
    /// let registry = ParserRegistry::new();
    /// assert!(registry.has_parser(FormatId::SpassCsv));
    /// assert!(!registry.has_parser(FormatId::ChromeCsv));
    /// ```
    #[must_use]
    pub fn has_parser(&self, id: FormatId) -> bool {
        self.parsers.contains_key(&id)
    }

    /// Auto-detects the format of the given data.
    ///
    /// This method iterates through all registered parsers and returns the
    /// format ID of the first parser that reports it can handle the data.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to analyze.
    ///
    /// # Returns
    ///
    /// Returns `Some(FormatId)` if a compatible parser is found, or `None` if
    /// no parser can handle the data.
    ///
    /// # Examples
    ///
    /// ```
    /// use spass::parser::{ParserRegistry, FormatId};
    ///
    /// let registry = ParserRegistry::new();
    /// let csv_data = b"URL,Username,Password,Name,Note\ntest,user,pass,Test,note";
    ///
    /// let format = registry.auto_detect(csv_data);
    /// assert_eq!(format, Some(FormatId::SpassCsv));
    /// ```
    #[must_use]
    pub fn auto_detect(&self, data: &[u8]) -> Option<FormatId> {
        self.parsers
            .iter()
            .find_map(|(format_id, (_, can_parse, _))| can_parse(data).then_some(*format_id))
    }

    /// Returns the name of the parser for the given format ID.
    ///
    /// # Arguments
    ///
    /// * `id` - The format identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// use spass::parser::{ParserRegistry, FormatId};
    ///
    /// let registry = ParserRegistry::new();
    /// let name = registry.parser_name(FormatId::SpassCsv);
    /// assert_eq!(name, Some("SPass CSV Parser"));
    /// ```
    #[must_use]
    pub fn parser_name(&self, id: FormatId) -> Option<&'static str> {
        self.parsers.get(&id).map(|(_, _, name)| *name)
    }

    /// Returns the number of registered parsers.
    ///
    /// # Examples
    ///
    /// ```
    /// use spass::parser::ParserRegistry;
    ///
    /// let registry = ParserRegistry::new();
    /// assert_eq!(registry.len(), 1); // SpassCsvParser is registered by default
    /// ```
    #[must_use]
    pub fn len(&self) -> usize {
        self.parsers.len()
    }

    /// Returns `true` if no parsers are registered.
    ///
    /// # Examples
    ///
    /// ```
    /// use spass::parser::ParserRegistry;
    ///
    /// let registry = ParserRegistry::new();
    /// assert!(!registry.is_empty()); // Has default parser
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.parsers.is_empty()
    }

    /// Returns an iterator over all registered format IDs.
    ///
    /// # Examples
    ///
    /// ```
    /// use spass::parser::{ParserRegistry, FormatId};
    ///
    /// let registry = ParserRegistry::new();
    /// let formats: Vec<_> = registry.formats().collect();
    /// assert!(formats.contains(&FormatId::SpassCsv));
    /// ```
    pub fn formats(&self) -> impl Iterator<Item = FormatId> + '_ {
        self.parsers.keys().copied()
    }
}

impl Default for ParserRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_registry_has_default_parsers() {
        let registry = ParserRegistry::new();
        assert!(!registry.is_empty());
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn test_has_parser() {
        let registry = ParserRegistry::new();
        assert!(registry.has_parser(FormatId::SpassCsv));
        assert!(!registry.has_parser(FormatId::ChromeCsv));
    }

    #[test]
    fn test_parse() {
        let registry = ParserRegistry::new();
        let data = b"URL,Username,Password,Name,Note\ntest,user,pass,Test,note";
        let result = registry.parse(FormatId::SpassCsv, data);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1);
    }

    #[test]
    fn test_parser_name() {
        let registry = ParserRegistry::new();
        let name = registry.parser_name(FormatId::SpassCsv);
        assert_eq!(name, Some("SPass CSV Parser"));
    }

    #[test]
    fn test_auto_detect_spass_csv() {
        let registry = ParserRegistry::new();
        let data = b"URL,Username,Password,Name,Note\ntest,user,pass,Test,note";

        let format = registry.auto_detect(data);
        assert_eq!(format, Some(FormatId::SpassCsv));
    }

    #[test]
    fn test_auto_detect_unknown_format() {
        let registry = ParserRegistry::new();
        let data = b"This is not a known format";

        let format = registry.auto_detect(data);
        assert_eq!(format, None);
    }

    #[test]
    fn test_formats_iterator() {
        let registry = ParserRegistry::new();
        let formats: Vec<_> = registry.formats().collect();

        assert_eq!(formats.len(), 1);
        assert!(formats.contains(&FormatId::SpassCsv));
    }
}
