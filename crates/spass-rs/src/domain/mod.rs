//! Core domain types and business logic.

mod error;
mod types;
mod version_status;

pub use error::{SpassError, SpassResult};
pub use types::{EntryPassword, Hex};
pub use version_status::{BestEffortReport, DecryptOutcome, ReportSource, VersionStatus};
