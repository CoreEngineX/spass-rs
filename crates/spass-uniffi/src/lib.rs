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
//! See `spass-docs/rfc/001-ios-uniffi-bridge.md` for the bridge design and
//! `spass-docs/rfc/012-best-effort-fallback.md` for the version-status
//! surface returned from [`decrypt`].

use spass::domain::{BestEffortReport, EntryPassword, ReportSource, VersionStatus};
use spass::format::SpassFormatVersion;
use spass::pipeline::DecryptionPipeline;

uniffi::setup_scaffolding!();

/// FFI-facing error.
///
/// Variants normalise `spass::SpassError` to what's actionable from Swift.
/// Detailed information is collapsed at this boundary to preserve the
/// side-channel safety baked into `spass::SpassError::Decryption`.
///
/// `UnknownVersion` is the contribution-loop variant: when the file's
/// version sentinel isn't recognised AND the lenient parser couldn't
/// resolve all 5 required columns, the report rides along so the iOS
/// consumer can show a Mail composer or a GitHub link without re-parsing
/// anything.
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

    /// File's version sentinel wasn't recognised and the lenient parser
    /// couldn't extract entries either. The report carries column names
    /// from the file header (no row data) so the consumer can build a
    /// contribution URL.
    #[error("unknown .spass version \"{}\"", report.sentinel)]
    UnknownVersion {
        /// Diagnostic; same payload `VersionStatus::BestEffort` carries.
        report: FfiBestEffortReport,
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
            spass::SpassError::UnknownVersionUnparseable(report) => Self::UnknownVersion {
                report: FfiBestEffortReport::from(*report),
            },
            // Required because spass::SpassError is #[non_exhaustive].
            _ => Self::Internal {
                message: "unknown error".into(),
            },
        }
    }
}

/// Diagnostic for a `.spass` file whose version this build doesn't strictly
/// know. Carries header column names only -- no row data -- so the Swift
/// layer can show the user exactly what's being sent before they tap Send.
///
/// Helper strings (subject, body, URLs) are precomputed at construction so
/// iOS can read them as plain struct fields. `UniFFI` Records can't carry
/// methods, hence the eager materialisation. The recomputation cost is one
/// small allocation per Best-Effort decrypt -- negligible compared to the
/// 70k-iteration PBKDF2 that already ran.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiBestEffortReport {
    /// Line-1 string from the file (e.g. `"32"`).
    pub sentinel: String,
    /// Header line verbatim. Column names only.
    pub header_line: String,
    /// Canonical column names the lenient parser matched.
    pub recognized_columns: Vec<String>,
    /// Canonical column names that were absent. Empty when the lenient
    /// path succeeded; populated on `SpassFfiError::UnknownVersion`.
    pub missing_required_columns: Vec<String>,
    /// Header column names we didn't match against the canonical set.
    pub unknown_columns: Vec<String>,
    /// Entries the lenient parser extracted. Zero on the failure path.
    pub entries_extracted: u64,
    /// Pre-built subject line for the mail composer or GitHub issue.
    pub subject: String,
    /// Pre-built multi-line body. Show the user verbatim before sending.
    pub body: String,
    /// Pre-built GitHub-issue URL. Use as the `SFSafariViewController`
    /// fallback when the user has no mail account configured.
    pub github_issue_url: String,
    /// Pre-built `mailto:support@coreenginex.com` URL. iOS prefers
    /// `MFMailComposeViewController` which has no URL-length limits;
    /// this field is here for symmetry with the web build and for the
    /// "user has no Mail.app but tapped Email anyway" fallback.
    pub mailto_url: String,
}

const SUPPORT_EMAIL: &str = "support@coreenginex.com";

impl From<BestEffortReport> for FfiBestEffortReport {
    fn from(r: BestEffortReport) -> Self {
        let subject = r.subject();
        let body = r.body(ReportSource::IosApp);
        let github_issue_url = r.github_issue_url(ReportSource::IosApp);
        let mailto_url = r.mailto_url(SUPPORT_EMAIL, ReportSource::IosApp);
        Self {
            sentinel: r.sentinel,
            header_line: r.header_line,
            recognized_columns: r.recognized_columns,
            missing_required_columns: r.missing_required_columns,
            unknown_columns: r.unknown_columns,
            entries_extracted: r.entries_extracted as u64,
            subject,
            body,
            github_issue_url,
            mailto_url,
        }
    }
}

/// Whether the decrypt went through a strict known-version parser or the
/// schema-driven lenient fallback. On the lenient path, the report rides
/// along so Swift can show the contribution prompt.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum FfiVersionStatus {
    /// File was parsed by a strict, version-specific parser.
    Known {
        /// Which strict version was matched (`"V30"` or `"V31"`).
        version: String,
    },
    /// File's sentinel was unrecognised; the lenient parser extracted what
    /// it could.
    BestEffort {
        /// Diagnostic + entry count.
        report: FfiBestEffortReport,
    },
}

impl From<VersionStatus> for FfiVersionStatus {
    fn from(s: VersionStatus) -> Self {
        match s {
            VersionStatus::Known { version } => Self::Known {
                version: format_version_name(version),
            },
            VersionStatus::BestEffort { report } => Self::BestEffort {
                report: FfiBestEffortReport::from(report),
            },
            // `VersionStatus` is `#[non_exhaustive]`; treat any future
            // variant as best-effort with a stub report so the iOS side
            // still surfaces something rather than silently dropping it.
            // The stub flows through the same domain `BestEffortReport`
            // so the precomputed helper strings stay populated.
            _ => Self::BestEffort {
                report: FfiBestEffortReport::from(BestEffortReport {
                    sentinel: "unknown".into(),
                    header_line: String::new(),
                    recognized_columns: Vec::new(),
                    missing_required_columns: Vec::new(),
                    unknown_columns: Vec::new(),
                    entries_extracted: 0,
                }),
            },
        }
    }
}

fn format_version_name(v: SpassFormatVersion) -> String {
    match v {
        SpassFormatVersion::V30 => "V30",
        SpassFormatVersion::V31 => "V31",
        // SpassFormatVersion is `#[non_exhaustive]`. Future variants get a
        // stringified placeholder so the Swift side at least sees something.
        _ => "Unknown",
    }
    .to_string()
}

/// Wire shape returned by [`decrypt`]: entries as JSON (same format the
/// Swift layer already parses) plus a structured version status.
///
/// Kept as a single struct so iOS receives the version signal alongside
/// the entries in one call -- no separate round trip needed.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiDecryptOutcome {
    /// Entries as a JSON-encoded array. Compact, same shape as
    /// `spass-wasm`'s `entries` field. Each element has `url`, `username`,
    /// `password`, `name`, `note`.
    pub entries_json: String,
    /// Strict path vs lenient-fallback path.
    pub version_status: FfiVersionStatus,
}

/// Decrypt a `.spass` file's text content and return entries + version
/// status.
///
/// `file_text` is the Base64 content of the file, exactly as Samsung Pass
/// writes it. `password` is the export password the user chose when
/// creating the file.
///
/// `FfiDecryptOutcome::entries_json` is a compact JSON-encoded array. Each
/// element has `url`, `username`, `password`, `name`, `note` -- always
/// present, never `null`. Empty collection serialises as `"[]"`. Same wire
/// shape `spass-wasm` returns to the web app.
///
/// Runs PBKDF2 at the production iteration count (70,000), which dominates
/// the runtime - expect 100-300 ms on iPhone XS, sub-50 ms on iPhone 15.
///
/// # Errors
///
/// - [`SpassFfiError::WrongPassword`] if the password is wrong or the
///   ciphertext is corrupt.
/// - [`SpassFfiError::InvalidFormat`] if the file is not a valid `.spass`
///   export.
/// - [`SpassFfiError::UnknownVersion`] if the file's version sentinel is
///   unrecognised AND the lenient parser couldn't resolve all 5 required
///   columns. The report carries the diagnostic for the contribution UI.
/// - [`SpassFfiError::Internal`] for I/O failures, configuration
///   mismatches, or the (theoretically impossible) JSON serialisation
///   failure on the result.
//
// `String` (not `&str`) is required by `UniFFI`'s wire format for owned strings;
// `clippy::needless_pass_by_value` is wrong about this signature.
// `result_large_err` is acceptable because the `Err` arm only materialises on
// the rare `UnknownVersion` path; the success path carries no precomputed
// strings in the Result discriminant.
#[uniffi::export]
#[allow(clippy::needless_pass_by_value, clippy::result_large_err)]
pub fn decrypt(file_text: String, password: String) -> Result<FfiDecryptOutcome, SpassFfiError> {
    let pipeline = DecryptionPipeline::default();
    let pw = EntryPassword::new(password);
    let outcome = pipeline.decrypt_string(&file_text, &pw)?;

    let entries_json =
        serde_json::to_string(&outcome.entries).map_err(|e| SpassFfiError::Internal {
            message: e.to_string(),
        })?;

    Ok(FfiDecryptOutcome {
        entries_json,
        version_status: FfiVersionStatus::from(outcome.version_status),
    })
}
