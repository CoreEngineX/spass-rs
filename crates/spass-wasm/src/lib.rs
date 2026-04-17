use spass::domain::EntryPassword;
use spass::pipeline::DecryptionPipeline;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn decrypt(file_text: &str, password: &str) -> Result<JsValue, JsValue> {
    let pipeline = DecryptionPipeline::default();
    let pw = EntryPassword::new(password.to_string());

    let collection = pipeline
        .decrypt_string(file_text, &pw)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let mut buf = Vec::with_capacity(collection.len() * 120 + 2);
    serde_json::to_writer(&mut buf, &collection)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let json = String::from_utf8(buf)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    Ok(JsValue::from_str(&json))
}
