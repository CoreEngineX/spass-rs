use spass::domain::{BestEffortReport, EntryPassword, ReportSource, VersionStatus};
use spass::pipeline::DecryptionPipeline;
use spass::SpassError;
use wasm_bindgen::prelude::*;

/// Decrypt a `.spass` file's text content. Returns a JSON object as a string:
///
/// ```text
/// { "entries": [...], "version_status": { "kind": "known", "version": "V31" } }
/// ```
///
/// or, for files whose version sentinel this crate doesn't strictly know:
///
/// ```text
/// { "entries": [...], "version_status": { "kind": "best_effort", "report": { ... } } }
/// ```
///
/// The report object carries the domain fields plus precomputed `subject`,
/// `body`, `github_issue_url`, and `mailto_url` strings (built with
/// [`ReportSource::WebApp`]), so the JS layer never formats the contribution
/// message itself -- mirroring how `spass-uniffi` precomputes the same
/// strings for iOS.
///
/// When the lenient parser can't resolve all 5 required columns, the JS-side
/// `catch` receives a JSON string whose shape is
/// `{ "kind": "unknown_version_unparseable", "report": { ... } }` (same
/// enriched report shape) so the web consumer can render the same
/// contribution UI it would for a successful best-effort parse.
#[wasm_bindgen]
pub fn decrypt(file_text: &str, password: &str) -> Result<JsValue, JsValue> {
    let pipeline = DecryptionPipeline::default();
    let pw = EntryPassword::new(password.to_string());

    let outcome = pipeline
        .decrypt_string(file_text, &pw)
        .map_err(js_err_for)?;

    let version_status = match &outcome.version_status {
        VersionStatus::Known { version } => serde_json::json!({
            "kind": "known",
            "version": version,
        }),
        VersionStatus::BestEffort { report } => serde_json::json!({
            "kind": "best_effort",
            "report": EnrichedReport::new(report),
        }),
        // `VersionStatus` is `#[non_exhaustive]`; a future variant passes
        // through under its own serde tag rather than dropping the entries
        // the pipeline already extracted.
        other => serde_json::to_value(other).map_err(|e| JsValue::from_str(&e.to_string()))?,
    };

    let json = serde_json::json!({
        "entries": &outcome.entries,
        "version_status": version_status,
    });
    Ok(JsValue::from_str(&json.to_string()))
}

/// Domain report plus the precomputed contribution strings. The eager
/// materialisation matches `spass-uniffi`'s `FfiBestEffortReport` so both
/// app platforms consume identical, core-authored message text.
#[derive(serde::Serialize)]
struct EnrichedReport<'a> {
    #[serde(flatten)]
    report: &'a BestEffortReport,
    subject: String,
    body: String,
    github_issue_url: String,
    mailto_url: String,
}

const SUPPORT_EMAIL: &str = "support@coreenginex.com";

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

/// Maps a `SpassError` to the `JsValue` the JS layer sees on a thrown promise.
/// `UnknownVersionUnparseable` is the load-bearing case: the JS catch handler
/// needs the diagnostic report to render the contribution prompt, so we
/// serialise it instead of falling back to the bare error message.
fn js_err_for(err: SpassError) -> JsValue {
    if let SpassError::UnknownVersionUnparseable(ref report) = err {
        if let Ok(json) = serde_json::to_string(&serde_json::json!({
            "kind": "unknown_version_unparseable",
            "report": EnrichedReport::new(report),
        })) {
            return JsValue::from_str(&json);
        }
    }
    JsValue::from_str(&err.to_string())
}
