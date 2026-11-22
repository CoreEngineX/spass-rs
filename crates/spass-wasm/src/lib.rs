use spass::EntryBuffer;
use spass::domain::{DecryptOutcome, EntryPassword};
use spass::pipeline::DecryptionPipeline;
use wasm_bindgen::prelude::*;

mod payload;

use payload::{Failure, version_status_json};

/// Owns the decrypted entries inside WebAssembly memory; `free()` zeroes and frees them.
///
/// Reading the fields means viewing `bytes_ptr()..bytes_ptr() + bytes_len()` of the module's
/// memory. Any later call into the module can grow that memory and detach every view of it, so a
/// reader takes its views after the last call and drops them before the next.
#[wasm_bindgen]
pub struct DecryptedEntries {
    entries: EntryBuffer,
    version_status: String,
}

impl DecryptedEntries {
    fn decrypt(file: &[u8], password: &str) -> Result<Self, Failure> {
        let password = EntryPassword::new(password.to_owned());
        let DecryptOutcome {
            entries,
            version_status,
        } = DecryptionPipeline::default().decrypt_to_buffer(file, &password)?;
        let version_status = version_status_json(&version_status)?;
        Ok(Self {
            entries,
            version_status,
        })
    }
}

// WebAssembly addresses are 32 bits and `decrypt_to_buffer` caps every buffer at 100 MiB, so the
// casts below are lossless in the module.
#[wasm_bindgen]
impl DecryptedEntries {
    pub fn count(&self) -> u32 {
        self.entries.len() as u32
    }

    /// Address of the whole buffer: fields, padding, then the index.
    pub fn bytes_ptr(&self) -> u32 {
        self.entries.as_bytes().as_ptr().addr() as u32
    }

    pub fn bytes_len(&self) -> u32 {
        self.entries.as_bytes().len() as u32
    }

    /// Offset of the index from `bytes_ptr()`; five little-endian `u32` field ends per entry.
    pub fn index_offset(&self) -> u32 {
        self.entries.index_offset() as u32
    }

    /// `{"kind":"known","version":"V31"}` or `{"kind":"best_effort","report":{...}}`; the report
    /// carries precomputed `subject`, `body`, `github_issue_url` and `mailto_url` strings.
    pub fn version_status(&self) -> String {
        self.version_status.clone()
    }
}

/// Decrypts a `.spass` file's bytes.
///
/// # Errors
///
/// Rejects with the error's message or, for an unknown version whose columns cannot be resolved,
/// the string `{"kind":"unknown_version_unparseable","report":{...}}`.
#[wasm_bindgen]
pub fn decrypt_entries(file: &[u8], password: &str) -> Result<DecryptedEntries, JsValue> {
    DecryptedEntries::decrypt(file, password)
        .map_err(|failure| JsValue::from_str(&failure.payload()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use spass::format::SpassFormatVersion;
    use spass::testkit::{SpassGenerator, TestEntry};

    const PASSWORD: &str = "TestPassword123";

    fn entries() -> Vec<TestEntry> {
        vec![
            TestEntry::new(
                "https://accounts.google.com",
                "user@gmail.com",
                "G00gle-p@ss",
                "Google",
                "Main, shared",
            ),
            TestEntry::new(
                "https://caf\u{e9}.example",
                "ユーザー",
                "p\u{e4}ssw\u{f6}rd-日本語-\u{1d518}\u{1d52b}",
                "Caf\u{e9}",
                "",
            ),
            TestEntry::new(
                "android://com.netflix.mediaclient",
                "stream@email.com",
                "Netfl1x!",
                "Netflix",
                "Family",
            ),
        ]
    }

    fn spass_file(version: SpassFormatVersion, entries: Vec<TestEntry>) -> String {
        SpassGenerator::new(PASSWORD)
            .with_version(version)
            .entries(entries)
            .generate()
    }

    fn unknown_sentinel_file(header: Vec<&'static str>) -> String {
        SpassGenerator::new(PASSWORD)
            .with_version(SpassFormatVersion::V31)
            .with_sentinel("33")
            .with_v31_header(header)
            .entries(entries())
            .generate()
    }

    fn decrypt(file: &str) -> DecryptedEntries {
        match DecryptedEntries::decrypt(file.as_bytes(), PASSWORD) {
            Ok(decrypted) => decrypted,
            Err(failure) => panic!("decrypt failed: {}", failure.payload()),
        }
    }

    fn rejection(file: &str, password: &str) -> String {
        match DecryptedEntries::decrypt(file.as_bytes(), password) {
            Ok(_) => panic!("decrypt unexpectedly succeeded"),
            Err(failure) => failure.payload(),
        }
    }

    fn to_usize(n: u32) -> usize {
        usize::try_from(n).expect("u32 fits usize")
    }

    /// Reads the fields the way the web reader does: from the bytes and the index alone.
    fn read_fields(bytes: &[u8], index_offset: usize, count: usize) -> Vec<[&str; 5]> {
        let (words, rest) = bytes[index_offset..].as_chunks::<4>();
        assert!(rest.is_empty());
        let ends: Vec<usize> = words
            .iter()
            .map(|word| to_usize(u32::from_le_bytes(*word)))
            .collect();
        let (rows, rest) = ends.as_chunks::<5>();
        assert!(rest.is_empty());
        assert_eq!(rows.len(), count);

        let mut start = 0;
        let mut fields = Vec::with_capacity(count);
        for row in rows {
            let mut entry = [""; 5];
            for (slot, end) in entry.iter_mut().zip(row) {
                *slot = str::from_utf8(&bytes[start..*end]).expect("field is UTF-8");
                start = *end;
            }
            fields.push(entry);
        }
        fields
    }

    #[test]
    fn numbers_describe_the_buffer() {
        let expected = entries();
        let decrypted = decrypt(&spass_file(SpassFormatVersion::V31, entries()));
        let bytes = decrypted.entries.as_bytes();
        let count = to_usize(decrypted.count());
        let index_offset = to_usize(decrypted.index_offset());

        assert_eq!(count, expected.len());
        assert_eq!(index_offset % 4, 0);
        assert_eq!(to_usize(decrypted.bytes_len()), bytes.len());
        assert_eq!(bytes.len(), index_offset + 20 * count);

        let fields = read_fields(bytes, index_offset, count);
        for (entry, want) in fields.iter().zip(&expected) {
            assert_eq!(
                *entry,
                [
                    want.url.as_str(),
                    want.username.as_str(),
                    want.password.as_str(),
                    want.name.as_str(),
                    want.note.as_str(),
                ]
            );
        }

        let field_bytes: usize = fields.iter().flatten().map(|field| field.len()).sum();
        assert!(index_offset >= field_bytes && index_offset - field_bytes < 4);
        assert!(bytes[field_bytes..index_offset].iter().all(|b| *b == 0));
    }

    #[test]
    fn an_empty_export_is_an_empty_buffer() {
        let decrypted = decrypt(&spass_file(SpassFormatVersion::V31, Vec::new()));

        assert_eq!(decrypted.count(), 0);
        assert_eq!(decrypted.index_offset(), 0);
        assert_eq!(decrypted.bytes_len(), 0);
    }

    #[test]
    fn known_versions_report_their_version() {
        for (version, name) in [
            (SpassFormatVersion::V30, "V30"),
            (SpassFormatVersion::V31, "V31"),
            (SpassFormatVersion::V32, "V32"),
        ] {
            let decrypted = decrypt(&spass_file(
                version,
                entries().into_iter().take(1).collect(),
            ));

            assert_eq!(
                decrypted.version_status(),
                format!(r#"{{"kind":"known","version":"{name}"}}"#)
            );
        }
    }

    #[test]
    fn an_unknown_sentinel_reports_best_effort_with_web_strings() {
        let decrypted = decrypt(&unknown_sentinel_file(
            SpassGenerator::canonical_v31_header(),
        ));
        let status: Value =
            serde_json::from_str(&decrypted.version_status()).expect("status is JSON");

        assert_eq!(status["kind"], "best_effort");
        let report = &status["report"];
        assert_eq!(report["sentinel"], "33");
        assert_eq!(report["entries_extracted"], 3);
        assert_eq!(report["missing_required_columns"], serde_json::json!([]));
        for key in ["subject", "body", "github_issue_url", "mailto_url"] {
            assert!(
                report[key].as_str().is_some_and(|text| !text.is_empty()),
                "{key} is missing"
            );
        }
        assert!(
            report["body"]
                .as_str()
                .is_some_and(|body| body.ends_with("Sent from the SPassPort web app\n"))
        );
        assert!(
            report["mailto_url"]
                .as_str()
                .is_some_and(|url| url.starts_with("mailto:support%40coreenginex.com?subject="))
        );
    }

    #[test]
    fn unresolvable_columns_reject_with_the_report() {
        let header = SpassGenerator::canonical_v31_header()
            .into_iter()
            .filter(|column| *column != "password_value")
            .collect();
        let payload: Value =
            serde_json::from_str(&rejection(&unknown_sentinel_file(header), PASSWORD))
                .expect("payload is JSON");

        assert_eq!(payload["kind"], "unknown_version_unparseable");
        assert_eq!(payload["report"]["sentinel"], "33");
        assert_eq!(
            payload["report"]["missing_required_columns"],
            serde_json::json!(["password_value"])
        );
    }

    #[test]
    fn a_wrong_password_rejects_with_the_decryption_message() {
        let message = rejection(
            &spass_file(SpassFormatVersion::V31, entries()),
            "wrong password",
        );

        assert!(message.contains("Decryption failed"), "{message}");
    }
}
