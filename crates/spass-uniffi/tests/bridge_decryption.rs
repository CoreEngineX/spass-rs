//! Integration tests for the FFI bridge.
//!
//! Fixtures are generated in-process via `spass::testkit` so the tests are
//! self-contained. They do not depend on any files in the workspace's `tmp/`
//! directory, which is gitignored and not present on CI runners.
//!
//! `decrypt` returns a JSON-encoded array as a single `String`; these tests
//! parse it and assert on the resulting structure - mirroring what the iOS
//! Swift caller does at runtime.

use serde_json::Value;
use spass::format::SpassFormatVersion;
use spass::testkit::{SpassGenerator, TestEntry};
use spass_uniffi::{decrypt, SpassFfiError};

const TEST_PASSWORD: &str = "TestPassword123";

fn fixture_with_n_entries(n: usize, password: &str) -> String {
    let entries: Vec<TestEntry> = (0..n)
        .map(|i| {
            TestEntry::new(
                format!("https://example{i}.com"),
                format!("user{i}@example.com"),
                format!("password{i}"),
                format!("Site {i}"),
                "",
            )
        })
        .collect();
    SpassGenerator::new(password).entries(entries).generate()
}

fn v31_fixture_with_n_entries(n: usize, password: &str) -> String {
    let entries: Vec<TestEntry> = (0..n)
        .map(|i| {
            TestEntry::new(
                format!("https://example{i}.com"),
                format!("user{i}@example.com"),
                format!("password{i}"),
                format!("Site {i}"),
                "",
            )
        })
        .collect();
    SpassGenerator::new(password)
        .with_version(SpassFormatVersion::V31)
        .entries(entries)
        .generate()
}

fn parse_entries(json: &str) -> Vec<Value> {
    let parsed: Value = serde_json::from_str(json).expect("decrypt() output must be valid JSON");
    parsed
        .as_array()
        .expect("decrypt() output must be a JSON array")
        .clone()
}

fn field<'a>(entry: &'a Value, key: &str) -> &'a str {
    entry[key]
        .as_str()
        .unwrap_or_else(|| panic!("missing or non-string `{key}` field on entry"))
}

#[test]
fn decrypts_one_entry_fixture() {
    let spass = fixture_with_n_entries(1, TEST_PASSWORD);
    let outcome =
        decrypt(spass, TEST_PASSWORD.into()).expect("a 1-entry fixture should round-trip");
    let entries = parse_entries(&outcome.entries_json);
    assert_eq!(entries.len(), 1);
}

#[test]
fn decrypts_multi_entry_fixture() {
    let spass = fixture_with_n_entries(8, TEST_PASSWORD);
    let outcome =
        decrypt(spass, TEST_PASSWORD.into()).expect("an 8-entry fixture should round-trip");
    let entries = parse_entries(&outcome.entries_json);
    assert_eq!(entries.len(), 8);
}

#[test]
fn entry_fields_round_trip() {
    let spass = SpassGenerator::new(TEST_PASSWORD)
        .entry(TestEntry::new(
            "https://example.com",
            "alice@example.com",
            "alicePassword!",
            "Example Account",
            "Test note",
        ))
        .generate();
    let outcome = decrypt(spass, TEST_PASSWORD.into()).expect("decrypt should succeed");
    let entries = parse_entries(&outcome.entries_json);
    let entry = entries.first().expect("at least one entry");
    assert_eq!(field(entry, "url"), "https://example.com");
    assert_eq!(field(entry, "username"), "alice@example.com");
    assert_eq!(field(entry, "password"), "alicePassword!");
    assert_eq!(field(entry, "name"), "Example Account");
    assert_eq!(field(entry, "note"), "Test note");
}

#[test]
fn zero_entry_fixture_errors_with_invalid_format() {
    // The CSV parser rejects a `.spass` file with zero entries as
    // `InvalidFormat` rather than producing an empty collection. The JSON
    // path inherits that.
    //
    // If the pipeline ever relaxes this and produces an empty collection,
    // the serialised result MUST be the literal string `"[]"` - never
    // `null`, never an empty object - because the Swift JSONSerialization
    // path expects the array shape unconditionally.
    let spass = fixture_with_n_entries(0, TEST_PASSWORD);
    let result = decrypt(spass, TEST_PASSWORD.into());
    match result {
        Err(SpassFfiError::InvalidFormat { .. }) => {}
        Err(other) => panic!("expected InvalidFormat for 0-entry fixture, got {other:?}"),
        Ok(_) => panic!("0-entry fixture currently errors; pipeline change required to allow it"),
    }
}

#[test]
fn decrypts_v31_fixture() {
    // v31 plaintext layout differs from v30 (35 cols, semicolon-delimited,
    // Base64-encoded values, &&&NULL&&& sentinel) but the bridge surface is
    // unchanged: same JSON-array shape, same fields per entry.
    let spass = v31_fixture_with_n_entries(5, TEST_PASSWORD);
    let outcome = decrypt(spass, TEST_PASSWORD.into()).expect("v31 fixture should round-trip");
    let entries = parse_entries(&outcome.entries_json);
    assert_eq!(entries.len(), 5);
    let first = entries.first().expect("at least one entry");
    assert_eq!(field(first, "url"), "https://example0.com");
    assert_eq!(field(first, "username"), "user0@example.com");
    assert_eq!(field(first, "password"), "password0");
    assert_eq!(field(first, "name"), "Site 0");
    assert_eq!(field(first, "note"), "");
}

#[test]
fn v31_field_mapping_round_trips() {
    // The v31 -> PasswordEntry projection must pull from the right columns:
    // origin_url, username_value, password_value, title, credential_memo --
    // not username_element / password_element / app_name / etc.
    let spass = SpassGenerator::new(TEST_PASSWORD)
        .with_version(SpassFormatVersion::V31)
        .entry(TestEntry::new(
            "android://com.example/login",
            "alice@example.com",
            "alicePassword!",
            "Example Account",
            "Test note",
        ))
        .generate();
    let outcome = decrypt(spass, TEST_PASSWORD.into()).expect("decrypt should succeed");
    let entries = parse_entries(&outcome.entries_json);
    let entry = entries.first().expect("at least one entry");
    assert_eq!(field(entry, "url"), "android://com.example/login");
    assert_eq!(field(entry, "username"), "alice@example.com");
    assert_eq!(field(entry, "password"), "alicePassword!");
    assert_eq!(field(entry, "name"), "Example Account");
    assert_eq!(field(entry, "note"), "Test note");
}

#[test]
fn special_characters_round_trip_through_json() {
    // Strings containing JSON-significant characters (`"`, `\`, `\n`, emoji)
    // must escape correctly on serialise and unescape correctly on parse.
    let spass = SpassGenerator::new(TEST_PASSWORD)
        .entry(TestEntry::new(
            "https://example.com/path?q=\"quoted\"",
            "user\\with\\backslashes",
            "p@ss\nwith\nnewlines",
            "Account 🔐",
            "Note with \"quotes\" and a tab\tcharacter",
        ))
        .generate();
    let outcome = decrypt(spass, TEST_PASSWORD.into()).expect("decrypt should succeed");
    let entries = parse_entries(&outcome.entries_json);
    let entry = entries.first().expect("at least one entry");
    assert_eq!(field(entry, "url"), "https://example.com/path?q=\"quoted\"");
    assert_eq!(field(entry, "username"), "user\\with\\backslashes");
    assert_eq!(field(entry, "password"), "p@ss\nwith\nnewlines");
    assert_eq!(field(entry, "name"), "Account 🔐");
    assert_eq!(
        field(entry, "note"),
        "Note with \"quotes\" and a tab\tcharacter"
    );
}

#[test]
fn wrong_password_on_v31_file_returns_wrong_password_variant() {
    // Version detection runs after AES decrypt, so a wrong password fails at
    // the crypto layer (before version is read) regardless of file format.
    // Tested explicitly here so the symmetry with v30 is recorded.
    let spass = v31_fixture_with_n_entries(3, TEST_PASSWORD);
    let result = decrypt(spass, "DefinitelyWrongPassword".into());
    match result {
        Err(SpassFfiError::WrongPassword) => {}
        Err(other) => panic!("expected WrongPassword on v31 file, got {other:?}"),
        Ok(_) => panic!("decryption should not succeed with wrong password on v31 file"),
    }
}

// Corrupted-v31-row coverage (wrong column count, malformed Base64) lives at
// the unit-test level in `parser/v31/tokenize.rs` -- those tests directly
// exercise the InvalidFormat surface with row-index messages. No need for a
// bridge-level duplicate here; the bridge propagates whatever the pipeline
// returns unchanged.

#[test]
fn wrong_password_returns_wrong_password_variant() {
    let spass = fixture_with_n_entries(1, TEST_PASSWORD);
    let result = decrypt(spass, "DefinitelyWrongPassword".into());
    match result {
        Err(SpassFfiError::WrongPassword) => {}
        Err(other) => panic!("expected WrongPassword, got {other:?}"),
        Ok(_) => panic!("decryption should not succeed with wrong password"),
    }
}

#[test]
fn corrupted_input_returns_invalid_format() {
    let result = decrypt("not-base64-not-anything".into(), TEST_PASSWORD.into());
    match result {
        Err(SpassFfiError::InvalidFormat { .. }) => {}
        Err(other) => panic!("expected InvalidFormat, got {other:?}"),
        Ok(_) => panic!("decryption should not succeed with garbage input"),
    }
}

#[test]
fn empty_input_returns_invalid_format_or_wrong_password() {
    let result = decrypt(String::new(), TEST_PASSWORD.into());
    assert!(
        matches!(
            result,
            Err(SpassFfiError::InvalidFormat { .. } | SpassFfiError::WrongPassword)
        ),
        "expected an InvalidFormat or WrongPassword error for empty input, got {result:?}"
    );
}
