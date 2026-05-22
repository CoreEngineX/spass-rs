//! Core domain types and business logic.

mod collection;
mod entry;
mod error;
mod types;
mod version_status;

pub use collection::PasswordEntryCollection;
pub use entry::{EntryType, PasswordEntry};
pub use error::{SpassError, SpassResult};
pub use types::{DecryptedData, EntryName, EntryPassword, Hex, Note, Url, Username};
pub use version_status::{BestEffortReport, DecryptOutcome, VersionStatus};
