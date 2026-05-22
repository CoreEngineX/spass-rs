use spass::domain::EntryPassword;
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
/// When the lenient parser can't resolve all 5 required columns, the JS-side
/// `catch` receives a JSON string whose shape is
/// `{ "kind": "unknown_version_unparseable", "report": { ... } }` so the web
/// consumer can render the same contribution UI it would for a successful
/// best-effort parse.
#[wasm_bindgen]
pub fn decrypt(file_text: &str, password: &str) -> Result<JsValue, JsValue> {
    let pipeline = DecryptionPipeline::default();
    let pw = EntryPassword::new(password.to_string());

    let outcome = pipeline
        .decrypt_string(file_text, &pw)
        .map_err(js_err_for)?;

    let json = serde_json::to_string(&outcome).map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(JsValue::from_str(&json))
}

/// Maps a `SpassError` to the `JsValue` the JS layer sees on a thrown promise.
/// `UnknownVersionUnparseable` is the load-bearing case: the JS catch handler
/// needs the diagnostic report to render the contribution prompt, so we
/// serialise it instead of falling back to the bare error message.
fn js_err_for(err: SpassError) -> JsValue {
    if let SpassError::UnknownVersionUnparseable(ref report) = err {
        if let Ok(json) = serde_json::to_string(&serde_json::json!({
            "kind": "unknown_version_unparseable",
            "report": &**report,
        })) {
            return JsValue::from_str(&json);
        }
    }
    JsValue::from_str(&err.to_string())
}
