#![warn(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

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
//! let collection = pipeline.decrypt_file("passwords.spass", &password)?;
//!
//! println!("Decrypted {} entries", collection.len());
//! # Ok::<(), spass::SpassError>(())
//! ```

pub mod crypto;
pub mod domain;
pub mod export;
pub mod format;
pub mod parser;
pub mod pipeline;

pub use domain::{SpassError, SpassResult};

#[cfg(any(test, feature = "generate-fixtures"))]
pub mod testkit;
