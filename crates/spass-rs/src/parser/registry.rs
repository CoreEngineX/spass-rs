//! Parser registry for managing and auto-detecting parsers.

use std::collections::HashMap;

use super::schema::SchemaParser;
use super::trait_def::{DataParser, FormatId};
use super::v30::SpassCsvV30Parser;
use crate::domain::{PasswordEntryCollection, SpassResult};

type ParseFn = Box<dyn Fn(&[u8]) -> SpassResult<PasswordEntryCollection> + Send + Sync>;

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
/// assert!(registry.has_parser(FormatId::SpassCsvV30));
/// assert!(registry.has_parser(FormatId::SpassCsvV31));
/// ```
pub struct ParserRegistry {
    parsers: HashMap<FormatId, (ParseFn, CanParseFn, &'static str)>,
}

impl ParserRegistry {
    /// Registry pre-populated with the two parsers this crate ships:
    /// [`SpassCsvV30Parser`] ([`FormatId::SpassCsvV30`]) and
    /// [`SchemaParser`] ([`FormatId::SpassCsvV31`] -- the id names the
    /// family's first version; the parser serves every 35-column layout).
    #[must_use]
    pub fn new() -> Self {
        let mut registry = Self {
            parsers: HashMap::new(),
        };

        registry.parsers.insert(
            SpassCsvV30Parser::FORMAT_ID,
            (
                Box::new(|data| SpassCsvV30Parser::new().parse(data)),
                Box::new(|data| SpassCsvV30Parser::new().can_parse(data)),
                SpassCsvV30Parser::NAME,
            ),
        );

        registry.parsers.insert(
            SchemaParser::FORMAT_ID,
            (
                Box::new(|data| SchemaParser::new().parse(data)),
                Box::new(|data| SchemaParser::new().can_parse(data)),
                SchemaParser::NAME,
            ),
        );

        registry
    }

    /// Runs the parser registered for `id` against `data`.
    ///
    /// # Errors
    ///
    /// `SpassError::Parsing` if no parser is registered for `id`, or
    /// if the parser itself rejects the data.
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

    /// `true` if a parser is registered for `id`.
    #[must_use]
    pub fn has_parser(&self, id: FormatId) -> bool {
        self.parsers.contains_key(&id)
    }

    /// Asks each registered parser whether it can handle `data` and
    /// returns the first match.
    ///
    /// The production pipeline does NOT use auto-detection -- it
    /// resolves the format from line 1 of the decrypted payload via
    /// the internal version-sentinel detector. This method is exposed
    /// for tooling that wants to recognise raw data outside the
    /// encrypted pipeline.
    #[must_use]
    pub fn auto_detect(&self, data: &[u8]) -> Option<FormatId> {
        self.parsers
            .iter()
            .find_map(|(format_id, (_, can_parse, _))| can_parse(data).then_some(*format_id))
    }

    /// Display name of the parser registered for `id`, or `None`
    /// if `id` isn't registered.
    #[must_use]
    pub fn parser_name(&self, id: FormatId) -> Option<&'static str> {
        self.parsers.get(&id).map(|(_, _, name)| *name)
    }

    /// Number of registered parsers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.parsers.len()
    }

    /// `true` when no parsers are registered. The default registry
    /// is never empty; this is here for the [`Vec`]-like API
    /// contract.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.parsers.is_empty()
    }

    /// Iterate over all registered format IDs in arbitrary order.
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
        assert_eq!(registry.len(), 2);
    }

    #[test]
    fn test_has_parser() {
        let registry = ParserRegistry::new();
        assert!(registry.has_parser(FormatId::SpassCsvV30));
        assert!(registry.has_parser(FormatId::SpassCsvV31));
        assert!(!registry.has_parser(FormatId::ChromeCsv));
    }

    #[test]
    fn test_parse_v30() {
        let registry = ParserRegistry::new();
        let data = b"URL,Username,Password,Name,Note\ntest,user,pass,Test,note";
        let result = registry.parse(FormatId::SpassCsvV30, data);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1);
    }

    #[test]
    fn test_parser_name_v30() {
        let registry = ParserRegistry::new();
        assert_eq!(
            registry.parser_name(FormatId::SpassCsvV30),
            Some("SPass CSV v30 Parser")
        );
    }

    #[test]
    fn test_parser_name_schema() {
        let registry = ParserRegistry::new();
        assert_eq!(
            registry.parser_name(FormatId::SpassCsvV31),
            Some("SPass 35-column schema parser")
        );
    }

    #[test]
    fn test_auto_detect_v30() {
        let registry = ParserRegistry::new();
        let data = b"URL,Username,Password,Name,Note\ntest,user,pass,Test,note";
        let format = registry.auto_detect(data);
        assert_eq!(format, Some(FormatId::SpassCsvV30));
    }

    #[test]
    fn test_auto_detect_unknown() {
        let registry = ParserRegistry::new();
        let format = registry.auto_detect(b"garbage");
        assert_eq!(format, None);
    }

    #[test]
    fn test_formats_iterator() {
        let registry = ParserRegistry::new();
        let formats: Vec<_> = registry.formats().collect();
        assert_eq!(formats.len(), 2);
        assert!(formats.contains(&FormatId::SpassCsvV30));
        assert!(formats.contains(&FormatId::SpassCsvV31));
    }
}
