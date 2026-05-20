use super::{EntryType, PasswordEntry};

/// A collection of password entries.
#[derive(Debug, Clone, Default)]
#[must_use]
pub struct PasswordEntryCollection {
    entries: Vec<PasswordEntry>,
}

impl PasswordEntryCollection {
    /// Empty collection. Equivalent to `Self::default()`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Empty collection with backing storage sized for `cap`
    /// entries. Prefer this when the entry count is known up front
    /// (the parser uses it after counting CSV rows).
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            entries: Vec::with_capacity(cap),
        }
    }

    /// Append `entry` to the end.
    pub fn push(&mut self, entry: PasswordEntry) {
        self.entries.push(entry);
    }

    /// Borrow all entries as a slice.
    #[must_use]
    pub fn entries(&self) -> &[PasswordEntry] {
        &self.entries
    }

    /// Filter entries by `entry_type` -- e.g. only the login rows or
    /// only the note rows from a mixed Samsung Pass export.
    pub fn entries_by_type(
        &self,
        entry_type: EntryType,
    ) -> impl Iterator<Item = &PasswordEntry> + '_ {
        self.entries
            .iter()
            .filter(move |entry| entry.entry_type() == entry_type)
    }

    /// Entries [`PasswordEntry::is_sensitive`] flags as high-risk
    /// (banking, crypto exchanges, etc.). Useful for UIs that want
    /// to surface a "consider rotating these first" affordance after
    /// import.
    pub fn sensitive_entries(&self) -> impl Iterator<Item = &PasswordEntry> + '_ {
        self.entries.iter().filter(|entry| entry.is_sensitive())
    }

    /// Total number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` when the collection has zero entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over entries in insertion order.
    pub fn iter(&self) -> std::slice::Iter<'_, PasswordEntry> {
        self.entries.iter()
    }
}

#[cfg(feature = "export-json")]
impl serde::Serialize for PasswordEntryCollection {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(self.entries.len()))?;
        for e in &self.entries {
            seq.serialize_element(e)?;
        }
        seq.end()
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
