use super::{EntryName, EntryPassword, Note, SpassError, SpassResult, Url, Username};

#[cfg(feature = "export-json")]
impl serde::Serialize for PasswordEntry {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(5))?;
        map.serialize_entry("url", self.url.as_str())?;
        map.serialize_entry("username", self.username.as_str())?;
        map.serialize_entry("password", self.password.as_str())?;
        map.serialize_entry("name", self.name.as_str())?;
        map.serialize_entry("note", self.note.as_str())?;
        map.end()
    }
}

/// Classifies a password entry by its URL scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryType {
    /// `http://` or `https://`
    Website,
    /// `android://`
    AndroidApp,
    /// Any other scheme or no scheme.
    Other,
}

/// A single decrypted password entry.
#[allow(missing_docs)]
#[derive(Debug, Clone)]
pub struct PasswordEntry {
    pub url: Url,
    pub username: Username,
    pub password: EntryPassword,
    pub name: EntryName,
    pub note: Note,
}

impl PasswordEntry {
    /// Constructs a `PasswordEntry` from raw strings.
    #[must_use]
    pub fn new(
        url: String,
        username: String,
        password: String,
        name: String,
        note: String,
    ) -> Self {
        PasswordEntry {
            url: Url::new(url),
            username: Username::new(username),
            password: EntryPassword::new(password),
            name: EntryName::new(name),
            note: Note::new(note),
        }
    }

    /// Constructs a `PasswordEntry` from a slice of at least 5 strings: `[url, username, password, name, note]`.
    ///
    /// # Errors
    ///
    /// Returns `SpassError::Validation` if fewer than 5 elements are provided.
    pub fn from_raw_strings(fields: &[String]) -> SpassResult<Self> {
        if fields.len() < 5 {
            return Err(SpassError::Validation(
                "Password entry must have at least 5 fields".to_string(),
            ));
        }

        Ok(Self::new(
            fields[0].clone(),
            fields[1].clone(),
            fields[2].clone(),
            fields[3].clone(),
            fields[4].clone(),
        ))
    }

    /// Returns `[url, username, password, name, note]` as a CSV record.
    #[must_use]
    pub fn to_csv_record(&self) -> [&str; 5] {
        [
            self.url.as_str(),
            self.username.as_str(),
            self.password.as_str(),
            self.name.as_str(),
            self.note.as_str(),
        ]
    }

    /// Classifies the entry by URL scheme.
    #[must_use]
    pub fn entry_type(&self) -> EntryType {
        if self.url.as_str().starts_with("android://") {
            EntryType::AndroidApp
        } else if self.url.as_str().starts_with("http://")
            || self.url.as_str().starts_with("https://")
        {
            EntryType::Website
        } else {
            EntryType::Other
        }
    }

    /// Returns `true` if the URL or name contains a financial or crypto keyword.
    #[must_use]
    pub fn is_sensitive(&self) -> bool {
        let url_lower = self.url.as_str().to_lowercase();
        let name_lower = self.name.as_str().to_lowercase();

        let sensitive_keywords = [
            "bank",
            "banking",
            "financial",
            "paypal",
            "visa",
            "mastercard",
            "credit",
            "debit",
            "wallet",
            "crypto",
            "bitcoin",
            "ethereum",
        ];

        sensitive_keywords
            .iter()
            .any(|&keyword| url_lower.contains(keyword) || name_lower.contains(keyword))
    }
}
