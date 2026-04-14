use super::{EntryType, PasswordEntry};

/// A collection of password entries.
#[derive(Debug, Clone, Default)]
#[must_use]
pub struct PasswordEntryCollection {
    entries: Vec<PasswordEntry>,
}

impl PasswordEntryCollection {
    /// Creates an empty collection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends an entry.
    pub fn push(&mut self, entry: PasswordEntry) {
        self.entries.push(entry);
    }

    /// Returns a slice of all entries.
    #[must_use]
    pub fn entries(&self) -> &[PasswordEntry] {
        &self.entries
    }

    /// Returns an iterator over entries matching `entry_type`.
    pub fn entries_by_type(
        &self,
        entry_type: EntryType,
    ) -> impl Iterator<Item = &PasswordEntry> + '_ {
        self.entries
            .iter()
            .filter(move |entry| entry.entry_type() == entry_type)
    }

    /// Returns an iterator over entries classified as sensitive (banking, crypto, etc.).
    pub fn sensitive_entries(&self) -> impl Iterator<Item = &PasswordEntry> + '_ {
        self.entries.iter().filter(|entry| entry.is_sensitive())
    }

    /// Returns the number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if there are no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns an iterator over entries.
    pub fn iter(&self) -> std::slice::Iter<'_, PasswordEntry> {
        self.entries.iter()
    }
}

impl From<Vec<PasswordEntry>> for PasswordEntryCollection {
    fn from(entries: Vec<PasswordEntry>) -> Self {
        Self { entries }
    }
}

impl<'a> IntoIterator for &'a PasswordEntryCollection {
    type Item = &'a PasswordEntry;
    type IntoIter = std::slice::Iter<'a, PasswordEntry>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl IntoIterator for PasswordEntryCollection {
    type Item = PasswordEntry;
    type IntoIter = std::vec::IntoIter<PasswordEntry>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}
