//! Outcome wrapper + version-status discriminator returned by the decryption pipeline.
//!
//! Two paths land here. A file whose line-1 sentinel is in the version
//! table (`"spass_export_v1"`, `"31"`, `"32"`) produces
//! `VersionStatus::Known`. A file whose sentinel is unrecognised runs the
//! same default schema parser as the known 35-column versions but produces
//! `VersionStatus::BestEffort` carrying a [`BestEffortReport`] -- the same
//! struct is also returned via `SpassError::UnknownVersionUnparseable`
//! when the schema parser can't resolve all 5 required columns.
//!
//! The report is the load-bearing piece for the "help us add support" loop:
//! consumers (CLI, web, iOS) format it into a GitHub-issue URL or a Mail
//! composer body so the user can send the diagnostic with one tap. The
//! invariant: the report carries column-name metadata only -- no row values,
//! no sample entries, no file fingerprint -- so the contact flow stays
//! consistent with the "nothing leaves the device" pitch.

use std::fmt::Write;

use crate::domain::PasswordEntryCollection;
use crate::format::SpassFormatVersion;

/// Diagnostic payload describing a file whose format version this crate
/// doesn't strictly know.
///
/// Populated by the schema parser. Contains only column-name metadata
/// from the file's header, never row data. Consumers feed it into the
/// helper methods below to build a contribution URL.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "export-json", derive(serde::Serialize))]
pub struct BestEffortReport {
    /// The line-1 version string from the file (e.g. `"32"`), preserved
    /// verbatim post-trim so the user-facing message names the real value.
    pub sentinel: String,
    /// The header line as Samsung wrote it. Column names only -- no row data.
    pub header_line: String,
    /// Canonical v31 column names that matched on lookup (subset of the 5
    /// required).
    pub recognized_columns: Vec<String>,
    /// Canonical v31 column names that were absent in the header. Empty on
    /// the success path; populated on `UnknownVersionUnparseable`.
    pub missing_required_columns: Vec<String>,
    /// Header column names we didn't match against the canonical set. Useful
    /// for triage when adding support for a new version.
    pub unknown_columns: Vec<String>,
    /// Rows extracted. Zero on the failure path.
    pub entries_extracted: usize,
}

/// Which surface is rendering the report. Stamps the body's closing
/// "Sent from ..." provenance line so support can tell which platform a
/// report came from; everything else in the body stays identical across
/// platforms. The phrase is a static compile-time string -- the report's
/// column-names-only privacy invariant is unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportSource {
    /// "Sent from the `SPassPort` iOS app" -- used by `spass-uniffi`.
    IosApp,
    /// "Sent from the `SPassPort` Android app" -- used by `spass-uniffi`.
    AndroidApp,
    /// "Sent from the `SPassPort` web app" -- used by `spass-wasm`.
    WebApp,
    /// "Sent from the spass CLI" -- used by `spass-cli`.
    Cli,
}

impl ReportSource {
    fn phrase(self) -> &'static str {
        match self {
            Self::IosApp => "the SPassPort iOS app",
            Self::AndroidApp => "the SPassPort Android app",
            Self::WebApp => "the SPassPort web app",
            Self::Cli => "the spass CLI",
        }
    }
}

impl BestEffortReport {
    /// Subject line for both the mailto and the GitHub issue templates.
    /// Takes no [`ReportSource`] deliberately -- the subject stays
    /// identical across platforms.
    #[must_use]
    pub fn subject(&self) -> String {
        if self.missing_required_columns.is_empty() {
            format!(
                "[SPassPort] Unknown .spass version \"{}\" - help add support",
                self.sentinel
            )
        } else {
            format!(
                "[SPassPort] Can't parse .spass version \"{}\" - help add support",
                self.sentinel
            )
        }
    }

    /// Multi-line plain-text body shared by the mail-composer and the
    /// GitHub-issue paths. Same text the user sees in their composer before
    /// hitting Send, so it has to read as a human-written report -- no
    /// machine-y prefixes, no implementation jargon. `source` stamps the
    /// closing "Sent from ..." line naming the platform.
    #[must_use]
    pub fn body(&self, source: ReportSource) -> String {
        let mut out = String::with_capacity(1024);
        let lenient_failed = !self.missing_required_columns.is_empty();

        if lenient_failed {
            out.push_str(
                "Hi,\n\n\
                 I tried to convert a Samsung Pass file with version \"",
            );
            out.push_str(&self.sentinel);
            out.push_str(
                "\" - a version this app doesn't support yet. The app couldn't \
                 extract my data because some required columns weren't found in \
                 the file header. Below is the diagnostic. No password data is \
                 included, only the column names.\n\n",
            );
        } else {
            out.push_str(
                "Hi,\n\n\
                 I tried to convert a Samsung Pass file with version \"",
            );
            out.push_str(&self.sentinel);
            out.push_str(
                "\" - a version this app doesn't fully support yet. The app \
                 extracted my data on a best-effort basis. Below is the \
                 diagnostic info. No password data is included, only the \
                 column names from the file header.\n\n",
            );
        }

        out.push_str("Sentinel: ");
        out.push_str(&self.sentinel);
        out.push_str("\nHeader: ");
        out.push_str(&self.header_line);
        out.push('\n');

        if lenient_failed {
            let _ = writeln!(
                out,
                "Missing required columns ({}): {}",
                self.missing_required_columns.len(),
                self.missing_required_columns.join(", ")
            );
            if !self.recognized_columns.is_empty() {
                let _ = writeln!(
                    out,
                    "Other recognized columns: {}",
                    self.recognized_columns.join(", ")
                );
            }
        } else {
            let _ = writeln!(
                out,
                "Recognized columns ({}): {}",
                self.recognized_columns.len(),
                self.recognized_columns.join(", ")
            );
        }

        if !self.unknown_columns.is_empty() {
            let _ = writeln!(
                out,
                "Unknown columns ({}): {}",
                self.unknown_columns.len(),
                self.unknown_columns.join(", ")
            );
        }
        let _ = writeln!(out, "Entries extracted: {}", self.entries_extracted);
        out.push('\n');

        if lenient_failed {
            out.push_str(
                "If you can confirm what the new column name maps to, support \
                 can ship in a day or two. Thanks!\n",
            );
        } else {
            out.push_str(
                "Sending this helps add full support for this version, which \
                 benefits everyone else with the same Samsung phone. Thanks!\n",
            );
        }

        let _ = write!(out, "\nSent from {}\n", source.phrase());

        out
    }

    /// Pre-formatted GitHub-issue URL. Hit-the-link-and-Submit flow for the
    /// CLI (which can't open a Mail composer) and the secondary fallback on
    /// iOS / web when the user has no mail client wired up.
    #[must_use]
    pub fn github_issue_url(&self, source: ReportSource) -> String {
        format!(
            "https://github.com/CoreEngineX/spass-rs/issues/new?title={}&body={}",
            percent_encode(&self.subject()),
            percent_encode(&self.body(source))
        )
    }

    /// Pre-formatted mailto URL with subject + body filled in. Used by the
    /// web consumer; iOS prefers `MFMailComposeViewController` (no URL length
    /// limit) and pulls `subject()` + `body()` directly.
    #[must_use]
    pub fn mailto_url(&self, to: &str, source: ReportSource) -> String {
        format!(
            "mailto:{}?subject={}&body={}",
            percent_encode(to),
            percent_encode(&self.subject()),
            percent_encode(&self.body(source))
        )
    }
}

/// Whether the file's version sentinel was in the known-version table.
#[derive(Debug, Clone)]
#[cfg_attr(
    feature = "export-json",
    derive(serde::Serialize),
    serde(tag = "kind", rename_all = "snake_case")
)]
#[non_exhaustive]
pub enum VersionStatus {
    /// File matched a version this crate ships strict support for.
    Known {
        /// Which strict version was matched.
        version: SpassFormatVersion,
    },
    /// File's sentinel was unrecognised. The schema parser extracted what
    /// it could; `report` carries the diagnostic for the contribution flow.
    BestEffort {
        /// Header columns + sentinel; pass through `BestEffortReport`
        /// helpers to build a contact URL.
        report: BestEffortReport,
    },
}

/// What [`crate::pipeline::DecryptionPipeline`] hands back when decryption
/// succeeds: the extracted entries plus the version status.
///
/// `#[must_use]` because dropping the outcome silently throws away the
/// `BestEffort` signal -- consumers should at minimum inspect
/// [`Self::version_status`] before discarding it.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "export-json", derive(serde::Serialize))]
#[must_use]
pub struct DecryptOutcome {
    /// Extracted password entries.
    pub entries: PasswordEntryCollection,
    /// Whether the file's version sentinel was recognised.
    pub version_status: VersionStatus,
}

/// Percent-encodes bytes outside the unreserved set per RFC 3986.
/// Kept inline rather than pulled from a crate because the encoded
/// payload is a one-shot URL and the dependency cost isn't worth it.
fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            _ => {
                let _ = write!(out, "%{byte:02X}");
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_report(sentinel: &str, missing: Vec<&str>) -> BestEffortReport {
        BestEffortReport {
            sentinel: sentinel.to_string(),
            header_line: "_id;origin_url;username_value;password_value;title;credential_memo"
                .to_string(),
            recognized_columns: vec![
                "origin_url".to_string(),
                "username_value".to_string(),
                "password_value".to_string(),
                "title".to_string(),
                "credential_memo".to_string(),
            ],
            missing_required_columns: missing.into_iter().map(String::from).collect(),
            unknown_columns: vec!["_id".to_string()],
            entries_extracted: 12,
        }
    }

    #[test]
    fn subject_switches_on_failure() {
        let success = fake_report("32", vec![]);
        let failure = fake_report("32", vec!["password_value"]);
        assert!(success.subject().contains("help add support"));
        assert!(failure.subject().contains("Can't parse"));
    }

    #[test]
    fn body_carries_sentinel_and_header() {
        let r = fake_report("32", vec![]);
        let body = r.body(ReportSource::Cli);
        assert!(body.contains("Sentinel: 32"));
        assert!(body.contains("origin_url"));
    }

    #[test]
    fn body_failure_variant_lists_missing() {
        let r = fake_report("32", vec!["password_value"]);
        let body = r.body(ReportSource::Cli);
        assert!(body.contains("Missing required columns"));
        assert!(body.contains("password_value"));
    }

    #[test]
    fn body_ends_with_provenance_line_per_source() {
        let r = fake_report("32", vec![]);
        assert!(r
            .body(ReportSource::IosApp)
            .ends_with("Sent from the SPassPort iOS app\n"));
        assert!(r
            .body(ReportSource::AndroidApp)
            .ends_with("Sent from the SPassPort Android app\n"));
        assert!(r
            .body(ReportSource::WebApp)
            .ends_with("Sent from the SPassPort web app\n"));
        assert!(r
            .body(ReportSource::Cli)
            .ends_with("Sent from the spass CLI\n"));
    }

    #[test]
    fn every_source_has_a_distinct_phrase() {
        let r = fake_report("32", vec![]);
        let bodies: Vec<String> = [
            ReportSource::IosApp,
            ReportSource::AndroidApp,
            ReportSource::WebApp,
            ReportSource::Cli,
        ]
        .into_iter()
        .map(|s| r.body(s))
        .collect();

        for (i, a) in bodies.iter().enumerate() {
            for b in bodies.iter().skip(i + 1) {
                assert_ne!(a, b, "two sources produced an identical body");
            }
        }
    }

    #[test]
    fn failure_variant_body_also_carries_provenance_line() {
        let r = fake_report("32", vec!["password_value"]);
        assert!(r
            .body(ReportSource::IosApp)
            .ends_with("Sent from the SPassPort iOS app\n"));
    }

    #[test]
    fn provenance_line_is_the_only_cross_platform_difference() {
        let r = fake_report("32", vec![]);
        let ios = r.body(ReportSource::IosApp);
        let web = r.body(ReportSource::WebApp);
        let ios_prefix = ios
            .strip_suffix("Sent from the SPassPort iOS app\n")
            .unwrap();
        let web_prefix = web
            .strip_suffix("Sent from the SPassPort web app\n")
            .unwrap();
        assert_eq!(ios_prefix, web_prefix);
    }

    #[test]
    fn github_url_has_title_and_body_params() {
        let r = fake_report("32", vec![]);
        let url = r.github_issue_url(ReportSource::Cli);
        assert!(url.starts_with("https://github.com/CoreEngineX/spass-rs/issues/new?"));
        assert!(url.contains("title="));
        assert!(url.contains("body="));
        assert!(url.contains("Sent%20from%20the%20spass%20CLI"));
    }

    #[test]
    fn mailto_url_encodes_spaces_and_brackets() {
        let r = fake_report("32", vec![]);
        let url = r.mailto_url("support@coreenginex.com", ReportSource::WebApp);
        // "support@coreenginex.com" round-trips with @ percent-encoded.
        assert!(url.starts_with("mailto:support%40coreenginex.com"));
        // Spaces in the subject become %20, square brackets become %5B / %5D.
        assert!(url.contains("%5BSPassPort%5D"));
        assert!(url.contains("%20"));
    }

    #[test]
    fn percent_encode_preserves_unreserved() {
        assert_eq!(percent_encode("foo-bar_baz~01"), "foo-bar_baz~01");
    }

    #[test]
    fn percent_encode_handles_at_and_brackets() {
        assert_eq!(percent_encode("a@b"), "a%40b");
        assert_eq!(percent_encode("[x]"), "%5Bx%5D");
    }
}
