#![warn(missing_docs)]
#![warn(clippy::all)]
#![warn(clippy::pedantic)]

//! `UniFFI` bridge that exposes `spass-rs` to Swift on iOS.
//!
//! Layer 2 sibling alongside `spass-cli` and `spass-wasm`. The only workspace
//! dependency is `spass` (Layer 1). Produces a static library that the iOS app
//! links via an xcframework, with Swift bindings generated at build time by
//! `uniffi-bindgen`.
//!
//! See `spass-docs/rfc/001-ios-uniffi-bridge.md` for the full design.

use spass::domain::EntryPassword;
use spass::pipeline::DecryptionPipeline;

uniffi::setup_scaffolding!();

/// FFI-facing error.
///
/// Three variants normalise the six-variant `spass::SpassError` to what's
/// actionable from Swift. Detailed information is collapsed at this boundary
/// to preserve the side-channel safety baked into `spass::SpassError::Decryption`.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum SpassFfiError {
    /// Password did not decrypt the file.
    ///
    /// Also surfaces for genuinely corrupted ciphertext - distinguishing the
    /// two would leak a padding oracle, and the user-facing fix is the same.
    #[error("wrong password")]
    WrongPassword,

    /// File is not a valid `.spass` export.
    ///
    /// Covers bad Base64, missing `next_table` marker, malformed CSV, and
    /// other structural problems detected before the crypto step.
    #[error("invalid file format: {message}")]
    InvalidFormat {
        /// Human-readable detail; safe to surface to the user.
        message: String,
    },

    /// Anything else - I/O failure, configuration mismatch, or a future error
    /// variant added to `spass::SpassError` after this bridge was last updated.
    #[error("internal error: {message}")]
    Internal {
        /// Human-readable detail; safe to log but may not be user-actionable.
        message: String,
    },
}

impl From<spass::SpassError> for SpassFfiError {
    fn from(err: spass::SpassError) -> Self {
        match err {
            spass::SpassError::Decryption(_) => Self::WrongPassword,
            spass::SpassError::Parsing(s) | spass::SpassError::Validation(s) => {
                Self::InvalidFormat { message: s }
            }
            spass::SpassError::Csv(e) => Self::InvalidFormat {
                message: e.to_string(),
            },
            spass::SpassError::Io(e) => Self::Internal {
                message: e.to_string(),
            },
            spass::SpassError::Config(s) => Self::Internal { message: s },
            // Required because spass::SpassError is #[non_exhaustive].
            _ => Self::Internal {
                message: "unknown error".into(),
            },
        }
    }
}

/// Decrypt a `.spass` file's text content and return entries as JSON.
///
/// `file_text` is the Base64 content of the file, exactly as Samsung Pass writes
/// it. `password` is the export password the user chose when creating the file.
///
/// Returns a compact JSON-encoded array. Each element has `url`, `username`,
/// `password`, `name`, `note` -- always present, never `null`. Empty collection
/// serialises as `"[]"`. Same wire shape `spass-wasm` returns to the web app.
///
/// Runs PBKDF2 at the production iteration count (70,000), which dominates the
/// runtime - expect 100-300 ms on iPhone XS, sub-50 ms on iPhone 15.
///
/// # Errors
///
/// - [`SpassFfiError::WrongPassword`] if the password is wrong or the ciphertext is corrupt.
/// - [`SpassFfiError::InvalidFormat`] if the file is not a valid `.spass` export.
/// - [`SpassFfiError::Internal`] for I/O failures, configuration mismatches, or
///   the (theoretically impossible) JSON serialisation failure on the result.
//
// `String` (not `&str`) is required by `UniFFI`'s wire format for owned strings;
// `clippy::needless_pass_by_value` is wrong about this signature.
#[uniffi::export]
#[allow(clippy::needless_pass_by_value)]
pub fn decrypt(file_text: String, password: String) -> Result<String, SpassFfiError> {
    let pipeline = DecryptionPipeline::default();
    let pw = EntryPassword::new(password);
    let collection = pipeline.decrypt_string(&file_text, &pw)?;

    serde_json::to_string(&collection).map_err(|e| SpassFfiError::Internal {
        message: e.to_string(),
    })
}
