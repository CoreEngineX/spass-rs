#![warn(missing_docs)]
#![warn(clippy::all)]
#![allow(clippy::module_name_repetitions)]
// Blanket `clippy::pedantic` is deliberately NOT set here. The gated subset
// lives in scripts/ci-check.sh as individual -W flags, matching what
// `cex ci-check --rust` enforces org-wide; a crate-level blanket turns on the
// advisory lints too, and does so regardless of the flags the gate passes.

//! Samsung Pass (`SPass`) decryption library.
//!
//! This library provides cryptographic operations to decrypt Samsung Pass password
//! manager export files (`.spass` files) and convert them to standard formats.
//!
//! # Security
//!
//! - All sensitive data is automatically zeroized on drop
//! - Constant-time operations prevent timing attacks
//! - No passwords are logged or exposed in error messages
//!
//! # Example
//!
//! ```no_run
//! use spass::pipeline::DecryptionPipeline;
//! use spass::domain::EntryPassword;
//!
//! let pipeline = DecryptionPipeline::new(spass::crypto::PBKDF2_ITERATIONS);
//! let password = EntryPassword::new("my_password".to_string());
//! let outcome = pipeline.decrypt_file("passwords.spass", &password)?;
//!
//! println!("Decrypted {} entries", outcome.entries.len());
//! # Ok::<(), spass::SpassError>(())
//! ```

pub mod crypto;
pub mod domain;
pub mod export;
pub mod format;
pub mod parser;
pub mod pipeline;

pub use domain::{
    BestEffortReport, DecryptOutcome, ReportSource, SpassError, SpassResult, VersionStatus,
};

#[cfg(any(test, feature = "generate-fixtures"))]
pub mod testkit;
