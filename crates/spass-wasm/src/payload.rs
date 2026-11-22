use spass::SpassError;
use spass::domain::{BestEffortReport, ReportSource, VersionStatus};

const SUPPORT_EMAIL: &str = "support@coreenginex.com";

/// Domain report plus the precomputed contribution strings, so the JS layer never formats the
/// message itself.
#[derive(serde::Serialize)]
struct EnrichedReport<'a> {
    #[serde(flatten)]
    report: &'a BestEffortReport,
    subject: String,
    body: String,
    github_issue_url: String,
    mailto_url: String,
}

impl<'a> EnrichedReport<'a> {
    fn new(report: &'a BestEffortReport) -> Self {
        Self {
            report,
            subject: report.subject(),
            body: report.body(ReportSource::WebApp),
            github_issue_url: report.github_issue_url(ReportSource::WebApp),
            mailto_url: report.mailto_url(SUPPORT_EMAIL, ReportSource::WebApp),
        }
    }
}

/// `{"kind":"known","version":"V31"}` or `{"kind":"best_effort","report":{...}}`.
pub(crate) fn version_status_json(status: &VersionStatus) -> Result<String, serde_json::Error> {
    let value = match status {
        VersionStatus::Known { version } => serde_json::json!({
            "kind": "known",
            "version": version,
        }),
        VersionStatus::BestEffort { report } => serde_json::json!({
            "kind": "best_effort",
            "report": EnrichedReport::new(report),
        }),
        // `VersionStatus` is `#[non_exhaustive]`: a variant added later passes through under its
        // own serde tag instead of dropping the entries already decrypted.
        other => serde_json::to_value(other)?,
    };
    serde_json::to_string(&value)
}

/// The string a rejected promise carries. `UnknownVersionUnparseable` is serialised so the JS
/// layer can render the contribution prompt; every other error is its message.
fn error_payload(err: &SpassError) -> String {
    if let SpassError::UnknownVersionUnparseable(report) = err
        && let Ok(json) = serde_json::to_string(&serde_json::json!({
            "kind": "unknown_version_unparseable",
            "report": EnrichedReport::new(report),
        }))
    {
        return json;
    }
    err.to_string()
}

pub(crate) enum Failure {
    Decrypt(SpassError),
    Status(serde_json::Error),
}

impl From<SpassError> for Failure {
    fn from(err: SpassError) -> Self {
        Self::Decrypt(err)
    }
}

impl From<serde_json::Error> for Failure {
    fn from(err: serde_json::Error) -> Self {
        Self::Status(err)
    }
}

impl Failure {
    pub(crate) fn payload(&self) -> String {
        match self {
            Self::Decrypt(err) => error_payload(err),
            Self::Status(err) => err.to_string(),
        }
    }
}
