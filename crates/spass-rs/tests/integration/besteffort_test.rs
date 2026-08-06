//! Best-effort fallback regression suite.
//!
//! Two layers:
//!
//! 1. **Fixture-based tests** (lines below using `FIXTURE_PATH`) decrypt the
//!    committed `gen-test/besteffort/synthetic-v33.spass` file. These catch
//!    regressions where a future change subtly alters the encryption or
//!    plaintext-shape contract -- a previously-emitted file no longer
//!    parsing is a real-world break we want loud.
//!
//! 2. **In-process tests** generate synthetic v31-shape files on the fly
//!    via `SpassGenerator::with_sentinel(...)` + `with_v31_header(...)`
//!    and run them through the full encrypt -> decrypt -> lenient-parse
//!    pipeline. These cover the variations a committed fixture set would
//!    be expensive to maintain: reorderings, extra columns, missing
//!    columns, multiple sentinels, unicode payloads.
//!
//! Together: the committed fixture catches encryption-contract drift; the
//! in-process tests catch lenient-parser correctness drift.
//!
//! Regenerate the committed fixture with:
//!   cargo test -p spass generate_besteffort_fixture -- --nocapture --ignored

use spass::domain::{EntryPassword, ReportSource, SpassError, VersionStatus};
use spass::format::SpassFormatVersion;
use spass::pipeline::DecryptionPipeline;
use spass::testkit::{SpassGenerator, TestEntry};

const FIXTURE_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../gen-test/besteffort/synthetic-v33.spass"
);
const TEST_PASSWORD: &str = "TestPassword123";

// In-process tests run the full encrypt -> decrypt -> parse pipeline at the
// production iteration count (70k PBKDF2). Each test pays ~50-100ms for the
// crypto; the matrix is small enough (~20 tests) that the suite still
// completes in a few seconds. We deliberately don't override iterations
// because the pipeline's `Default` path is what consumers actually use.
fn production_pipeline() -> DecryptionPipeline {
    DecryptionPipeline::default()
}

fn password() -> EntryPassword {
    EntryPassword::new(TEST_PASSWORD.to_string())
}

fn sample_entries() -> Vec<TestEntry> {
    vec![
        TestEntry::new(
            "https://accounts.google.com",
            "user@gmail.com",
            "GooglePass!1",
            "Google",
            "Personal",
        ),
        TestEntry::new(
            "https://github.com",
            "devuser",
            "gh_token_abc123",
            "GitHub",
            "",
        ),
        TestEntry::new(
            "android://com.netflix.mediaclient",
            "user@gmail.com",
            "Netflix!2026",
            "Netflix",
            "Family plan",
        ),
    ]
}

// =============================================================================
// Section 1: committed-fixture regression tests
// =============================================================================

#[test]
fn besteffort_fixture_decrypts_through_lenient_path() {
    let outcome = production_pipeline()
        .decrypt_file(FIXTURE_PATH, &password())
        .expect("besteffort fixture should decrypt through lenient parser");

    assert_eq!(outcome.entries.len(), 5);

    let report = match outcome.version_status {
        VersionStatus::BestEffort { report } => report,
        VersionStatus::Known { version } => panic!("expected BestEffort, got Known({version:?})"),
        _ => panic!("expected BestEffort, got an unknown VersionStatus variant"),
    };

    assert_eq!(report.sentinel, "33");
    assert_eq!(report.entries_extracted, 5);
    assert!(
        report.missing_required_columns.is_empty(),
        "expected all 5 required columns to resolve, missing: {:?}",
        report.missing_required_columns
    );
    assert_eq!(report.recognized_columns.len(), 5);
}

#[test]
fn besteffort_fixture_entries_match_generator() {
    let outcome = production_pipeline()
        .decrypt_file(FIXTURE_PATH, &password())
        .expect("besteffort fixture should decrypt");
    let entries = outcome.entries.entries();

    // Mirrors what testkit's `generate_besteffort_fixture` writes.
    let expected = [
        (
            "https://accounts.google.com",
            "alex.morgan@gmail.com",
            "Google",
        ),
        ("https://github.com", "alexmorgan", "GitHub"),
        ("https://netflix.com", "alex.morgan@gmail.com", "Netflix"),
        (
            "android://com.samsung.android.app.samsungpay",
            "alex.morgan@gmail.com",
            "Samsung Pay",
        ),
        ("https://apple.com", "alex.morgan@icloud.com", "Apple ID"),
    ];

    assert_eq!(entries.len(), expected.len());
    for (entry, (url, username, name)) in entries.iter().zip(expected.iter()) {
        assert_eq!(entry.url.as_str(), *url);
        assert_eq!(entry.username.as_str(), *username);
        assert_eq!(entry.name.as_str(), *name);
        assert!(!entry.password.as_str().is_empty());
    }
}

#[test]
fn besteffort_fixture_enumerates_unknown_columns_in_report() {
    let outcome = production_pipeline()
        .decrypt_file(FIXTURE_PATH, &password())
        .unwrap();
    let report = match outcome.version_status {
        VersionStatus::BestEffort { report } => report,
        other => panic!("expected BestEffort, got {other:?}"),
    };

    assert_eq!(
        report.unknown_columns.len(),
        30,
        "expected 30 unknown columns (35 header - 5 required), got {}: {:?}",
        report.unknown_columns.len(),
        report.unknown_columns
    );

    let expected_unknown_sample = [
        "_id",
        "action_url",
        "username_element",
        "password_element",
        "favicon",
        "app_name",
        "package_name",
        "created_time",
        "modified_time",
        "otp",
    ];
    for name in expected_unknown_sample {
        assert!(
            report.unknown_columns.iter().any(|c| c == name),
            "expected `{name}` in unknown_columns, got {:?}",
            report.unknown_columns
        );
    }

    let body = report.body(ReportSource::Cli);
    assert!(body.contains("Unknown columns"));
    assert!(body.contains("_id"));
    assert!(body.contains("favicon"));
}

#[test]
fn besteffort_fixture_report_helpers_produce_contribution_urls() {
    let outcome = production_pipeline()
        .decrypt_file(FIXTURE_PATH, &password())
        .unwrap();
    let report = match outcome.version_status {
        VersionStatus::BestEffort { report } => report,
        other => panic!("expected BestEffort, got {other:?}"),
    };

    let subject = report.subject();
    assert!(subject.contains("33"));
    assert!(subject.contains("SPassPort"));

    let body = report.body(ReportSource::Cli);
    assert!(body.contains("Sentinel: 33"));
    assert!(body.contains("origin_url"));
    assert!(body.contains("credential_memo"));
    assert!(body.contains("Entries extracted: 5"));

    let issue_url = report.github_issue_url(ReportSource::Cli);
    assert!(issue_url.starts_with("https://github.com/CoreEngineX/spass-rs/issues/new?"));
    assert!(issue_url.contains("title="));
    assert!(issue_url.contains("body="));

    let mail_url = report.mailto_url("support@coreenginex.com", ReportSource::Cli);
    assert!(mail_url.starts_with("mailto:support%40coreenginex.com"));
}

#[test]
fn besteffort_fixture_wrong_password_returns_decryption_error() {
    // Sentinel detection runs after AES decrypt, so a wrong password fails at
    // the crypto layer regardless of file version. Confirms the besteffort
    // fixture doesn't accidentally bypass crypto checks.
    let result = production_pipeline().decrypt_file(
        FIXTURE_PATH,
        &EntryPassword::new("WrongPassword".to_string()),
    );
    match result {
        Err(SpassError::Decryption(_)) => {}
        Err(other) => panic!("expected Decryption error on wrong password, got {other:?}"),
        Ok(_) => panic!("decryption should not succeed with wrong password"),
    }
}

#[test]
fn besteffort_fixture_sentinel_preserved_verbatim_in_report() {
    // The sentinel string in BestEffortReport must match what's on line 1
    // of the file exactly -- no normalization, no trimming surprises. The
    // contribution-loop UX depends on showing the user the literal value.
    let outcome = production_pipeline()
        .decrypt_file(FIXTURE_PATH, &password())
        .unwrap();
    if let VersionStatus::BestEffort { report } = outcome.version_status {
        assert_eq!(report.sentinel, "33");
        assert!(!report.sentinel.starts_with(' '));
        assert!(!report.sentinel.ends_with(' '));
    } else {
        panic!("expected BestEffort");
    }
}

#[test]
fn besteffort_fixture_header_line_round_trips_into_report() {
    // The `header_line` field is the diagnostic that goes into the user's
    // contribution email. It must be the exact bytes Samsung emits.
    let outcome = production_pipeline()
        .decrypt_file(FIXTURE_PATH, &password())
        .unwrap();
    if let VersionStatus::BestEffort { report } = outcome.version_status {
        // 35 semicolon-separated columns -> 34 separators.
        assert_eq!(
            report.header_line.matches(';').count(),
            34,
            "header_line should have 34 semicolons (35 columns)"
        );
        assert!(report.header_line.starts_with("_id;origin_url;"));
        assert!(report.header_line.ends_with(";parent_id"));
    } else {
        panic!("expected BestEffort");
    }
}

// =============================================================================
// Section 2: sentinel-variation tests (in-process)
// =============================================================================

/// Builds an encrypted blob from a sentinel + canonical v31 shape + entries,
/// using deterministic salt/IV at the production iteration count. Slow per
/// call (~50ms PBKDF2) but the small test count keeps total runtime tight.
fn build_v31_shape_with_sentinel(sentinel: &str, entries: Vec<TestEntry>) -> String {
    SpassGenerator::new(TEST_PASSWORD)
        .with_version(SpassFormatVersion::V31)
        .with_sentinel(sentinel)
        .with_salt([0x33; 20])
        .with_iv([0x44; 16])
        .entries(entries)
        .generate()
}

#[test]
fn sentinel_32_decrypts_as_known_v32() {
    let blob = build_v31_shape_with_sentinel("32", sample_entries());
    let outcome = production_pipeline()
        .decrypt_string(&blob, &password())
        .unwrap();
    assert_eq!(outcome.entries.len(), sample_entries().len());
    match outcome.version_status {
        VersionStatus::Known { version } => {
            assert_eq!(version, SpassFormatVersion::V32);
        }
        other => panic!("expected Known V32, got {other:?}"),
    }
}

#[test]
fn v32_with_reordered_columns_and_extra_preamble_stays_known() {
    // The schema parser resolves columns by name and finds next_table
    // itself, so a v32 that drifts within the family shape still parses
    // as Known.
    let blob_bytes = {
        let mut columns = SpassGenerator::canonical_v31_header();
        // Swap title ahead of origin_url.
        let t = columns.iter().position(|c| *c == "title").unwrap();
        let o = columns.iter().position(|c| *c == "origin_url").unwrap();
        columns.swap(t, o);
        SpassGenerator::new(TEST_PASSWORD)
            .with_version(SpassFormatVersion::V32)
            .with_v31_header(columns)
            .entries(sample_entries())
            .generate()
    };
    let outcome = production_pipeline()
        .decrypt_string(&blob_bytes, &password())
        .unwrap();
    assert_eq!(outcome.entries.len(), sample_entries().len());
    assert!(matches!(
        outcome.version_status,
        VersionStatus::Known {
            version: SpassFormatVersion::V32
        }
    ));
    let e = &outcome.entries.entries()[0];
    assert_eq!(e.url.as_str(), sample_entries()[0].url);
    assert_eq!(e.name.as_str(), sample_entries()[0].name);
}

#[test]
fn sentinel_33_routes_through_besteffort() {
    let blob = build_v31_shape_with_sentinel("33", sample_entries());
    let outcome = production_pipeline()
        .decrypt_string(&blob, &password())
        .unwrap();
    match outcome.version_status {
        VersionStatus::BestEffort { report } => assert_eq!(report.sentinel, "33"),
        other => panic!("expected BestEffort, got {other:?}"),
    }
}

#[test]
fn sentinel_with_letters_routes_through_besteffort() {
    // Future versions might use a non-numeric sentinel. The lenient path
    // must accept any non-empty string -- the lookup is by column name in
    // the header, not by sentinel value.
    let blob = build_v31_shape_with_sentinel("v32-beta", sample_entries());
    let outcome = production_pipeline()
        .decrypt_string(&blob, &password())
        .unwrap();
    match outcome.version_status {
        VersionStatus::BestEffort { report } => assert_eq!(report.sentinel, "v32-beta"),
        other => panic!("expected BestEffort, got {other:?}"),
    }
}

#[test]
fn very_long_sentinel_preserved_in_report() {
    let long_sentinel = "spass_export_v_future_with_a_long_descriptive_name_2030_q4";
    let blob = build_v31_shape_with_sentinel(long_sentinel, sample_entries());
    let outcome = production_pipeline()
        .decrypt_string(&blob, &password())
        .unwrap();
    match outcome.version_status {
        VersionStatus::BestEffort { report } => assert_eq!(report.sentinel, long_sentinel),
        other => panic!("expected BestEffort, got {other:?}"),
    }
}

// =============================================================================
// Section 3: column-layout variation tests (in-process)
// =============================================================================

#[test]
fn lenient_handles_reordered_canonical_columns() {
    // Required columns at non-canonical positions. The lenient parser keys
    // on name, not index, so this must work.
    let header = vec![
        "credential_memo", // was at 31
        "title",           // was at 17
        "password_value",  // was at 7
        "username_value",  // was at 4
        "origin_url",      // was at 1
        "_id",             // was at 0
        "favicon",         // was at 18
    ];

    let blob = SpassGenerator::new(TEST_PASSWORD)
        .with_version(SpassFormatVersion::V31)
        .with_sentinel("33")
        .with_v31_header(header)
        .with_salt([0x55; 20])
        .with_iv([0x66; 16])
        .entries(sample_entries())
        .generate();

    let outcome = production_pipeline()
        .decrypt_string(&blob, &password())
        .unwrap();
    assert_eq!(outcome.entries.len(), 3);

    let entries = outcome.entries.entries();
    assert_eq!(entries[0].url.as_str(), "https://accounts.google.com");
    assert_eq!(entries[0].username.as_str(), "user@gmail.com");
    assert_eq!(entries[0].password.as_str(), "GooglePass!1");
    assert_eq!(entries[0].name.as_str(), "Google");
    assert_eq!(entries[0].note.as_str(), "Personal");

    if let VersionStatus::BestEffort { report } = outcome.version_status {
        assert!(report.missing_required_columns.is_empty());
        assert_eq!(report.recognized_columns.len(), 5);
    } else {
        panic!("expected BestEffort");
    }
}

#[test]
fn lenient_handles_extra_columns_appended_to_canonical() {
    // Future Samsung v32 likely appends new columns. Confirm the parser
    // doesn't choke on a 38-column header (canonical 35 + 3 new).
    let mut header = SpassGenerator::canonical_v31_header();
    header.push("brand_new_2fa_method");
    header.push("brand_new_biometric_id");
    header.push("brand_new_recovery_token");

    let blob = SpassGenerator::new(TEST_PASSWORD)
        .with_version(SpassFormatVersion::V31)
        .with_sentinel("33")
        .with_v31_header(header)
        .with_salt([0x77; 20])
        .with_iv([0x88; 16])
        .entries(sample_entries())
        .generate();

    let outcome = production_pipeline()
        .decrypt_string(&blob, &password())
        .unwrap();
    assert_eq!(outcome.entries.len(), 3);
    if let VersionStatus::BestEffort { report } = outcome.version_status {
        assert!(report
            .unknown_columns
            .contains(&"brand_new_2fa_method".to_string()));
        assert!(report
            .unknown_columns
            .contains(&"brand_new_biometric_id".to_string()));
        assert!(report
            .unknown_columns
            .contains(&"brand_new_recovery_token".to_string()));
        // 30 originally-unknown + 3 new = 33 total
        assert_eq!(report.unknown_columns.len(), 33);
    } else {
        panic!("expected BestEffort");
    }
}

#[test]
fn lenient_handles_extra_columns_inserted_between_canonical() {
    // New column between origin_url and username_value. Index lookup must
    // adapt; position-based parsing would silently grab wrong data here.
    let header = vec![
        "_id",
        "origin_url",
        "new_column_at_idx_2",
        "username_value",
        "another_new_column",
        "password_value",
        "title",
        "credential_memo",
    ];

    let blob = SpassGenerator::new(TEST_PASSWORD)
        .with_version(SpassFormatVersion::V31)
        .with_sentinel("33")
        .with_v31_header(header)
        .with_salt([0x99; 20])
        .with_iv([0xaa; 16])
        .entries(sample_entries())
        .generate();

    let outcome = production_pipeline()
        .decrypt_string(&blob, &password())
        .unwrap();
    let entries = outcome.entries.entries();
    assert_eq!(entries[0].username.as_str(), "user@gmail.com");
    assert_eq!(entries[0].password.as_str(), "GooglePass!1");
}

#[test]
fn lenient_handles_minimal_header_with_only_required_columns() {
    // Smallest possible v31-shape: just the 5 required columns. The parser
    // must still extract correctly.
    let header = vec![
        "origin_url",
        "username_value",
        "password_value",
        "title",
        "credential_memo",
    ];

    let blob = SpassGenerator::new(TEST_PASSWORD)
        .with_version(SpassFormatVersion::V31)
        .with_sentinel("33")
        .with_v31_header(header)
        .with_salt([0xbb; 20])
        .with_iv([0xcc; 16])
        .entries(sample_entries())
        .generate();

    let outcome = production_pipeline()
        .decrypt_string(&blob, &password())
        .unwrap();
    assert_eq!(outcome.entries.len(), 3);
    if let VersionStatus::BestEffort { report } = outcome.version_status {
        assert_eq!(report.recognized_columns.len(), 5);
        assert!(report.unknown_columns.is_empty());
        assert!(report.missing_required_columns.is_empty());
    } else {
        panic!("expected BestEffort");
    }
}

// =============================================================================
// Section 4: failure-path (UnknownVersionUnparseable) tests
// =============================================================================

#[test]
fn missing_password_column_produces_unparseable_with_diagnostic() {
    // password_value removed from canonical header. Lenient should fail
    // with UnknownVersionUnparseable carrying a usable diagnostic.
    let header: Vec<&'static str> = SpassGenerator::canonical_v31_header()
        .into_iter()
        .filter(|c| *c != "password_value")
        .collect();

    let blob = SpassGenerator::new(TEST_PASSWORD)
        .with_version(SpassFormatVersion::V31)
        .with_sentinel("33")
        .with_v31_header(header)
        .with_salt([0xdd; 20])
        .with_iv([0xee; 16])
        .entries(sample_entries())
        .generate();

    let err = production_pipeline()
        .decrypt_string(&blob, &password())
        .unwrap_err();
    match err {
        SpassError::UnknownVersionUnparseable(report) => {
            assert_eq!(report.sentinel, "33");
            assert_eq!(report.missing_required_columns, vec!["password_value"]);
            assert_eq!(report.entries_extracted, 0);
            // Recognized + unknown still populated for the user-facing diff.
            assert_eq!(report.recognized_columns.len(), 4);
            // Header had 34 columns (35 - 1) and 4 were recognized -> 30 unknown.
            assert_eq!(report.unknown_columns.len(), 30);
        }
        other => panic!("expected UnknownVersionUnparseable, got {other:?}"),
    }
}

#[test]
fn missing_multiple_required_columns_lists_all_in_report() {
    // Drop username_value AND password_value AND title -- the report must
    // enumerate all three so the user-facing email body lists what's needed.
    let header: Vec<&'static str> = SpassGenerator::canonical_v31_header()
        .into_iter()
        .filter(|c| !matches!(*c, "username_value" | "password_value" | "title"))
        .collect();

    let blob = SpassGenerator::new(TEST_PASSWORD)
        .with_version(SpassFormatVersion::V31)
        .with_sentinel("33")
        .with_v31_header(header)
        .with_salt([0x12; 20])
        .with_iv([0x34; 16])
        .entries(sample_entries())
        .generate();

    let err = production_pipeline()
        .decrypt_string(&blob, &password())
        .unwrap_err();
    match err {
        SpassError::UnknownVersionUnparseable(report) => {
            let missing: std::collections::HashSet<&str> = report
                .missing_required_columns
                .iter()
                .map(String::as_str)
                .collect();
            assert!(missing.contains("username_value"));
            assert!(missing.contains("password_value"));
            assert!(missing.contains("title"));
            assert_eq!(report.missing_required_columns.len(), 3);

            // Body must list every missing name so the recipient sees all 3.
            let body = report.body(ReportSource::Cli);
            assert!(body.contains("username_value"));
            assert!(body.contains("password_value"));
            assert!(body.contains("title"));
        }
        other => panic!("expected UnknownVersionUnparseable, got {other:?}"),
    }
}

#[test]
fn all_required_columns_missing_returns_full_diagnostic() {
    // Header contains only unknown columns. The report's
    // missing_required_columns should list all 5 canonical names.
    let header = vec!["field_a", "field_b", "field_c", "favicon", "app_name"];

    let blob = SpassGenerator::new(TEST_PASSWORD)
        .with_version(SpassFormatVersion::V31)
        .with_sentinel("99")
        .with_v31_header(header)
        .with_salt([0x56; 20])
        .with_iv([0x78; 16])
        .entries(sample_entries())
        .generate();

    let err = production_pipeline()
        .decrypt_string(&blob, &password())
        .unwrap_err();
    match &err {
        SpassError::UnknownVersionUnparseable(report) => {
            assert_eq!(report.missing_required_columns.len(), 5);
            assert!(report.recognized_columns.is_empty());
            assert_eq!(report.unknown_columns.len(), 5);
            assert_eq!(report.entries_extracted, 0);

            // Display impl must include the sentinel and missing-column list.
            let display = err.to_string();
            assert!(display.contains("99"));
            assert!(display.contains("origin_url"));
        }
        other => panic!("expected UnknownVersionUnparseable, got {other:?}"),
    }
}

#[test]
fn unparseable_error_display_contains_sentinel_and_missing() {
    // Defensive: the Display impl must include enough info for log lines
    // to be useful even when the consumer never opens the report.
    let header: Vec<&'static str> = SpassGenerator::canonical_v31_header()
        .into_iter()
        .filter(|c| *c != "credential_memo")
        .collect();

    let blob = SpassGenerator::new(TEST_PASSWORD)
        .with_version(SpassFormatVersion::V31)
        .with_sentinel("v33-experimental")
        .with_v31_header(header)
        .with_salt([0x9a; 20])
        .with_iv([0xbc; 16])
        .entries(sample_entries())
        .generate();

    let err = production_pipeline()
        .decrypt_string(&blob, &password())
        .unwrap_err();
    let s = err.to_string();
    assert!(s.contains("v33-experimental"), "got: {s}");
    assert!(s.contains("credential_memo"), "got: {s}");
}

// =============================================================================
// Section 5: data-payload variation tests (in-process)
// =============================================================================

#[test]
fn lenient_round_trips_unicode_in_entries() {
    let entries = vec![TestEntry::new(
        "https://accounts.example.中国",
        "user.李四@example.com",
        "P@sswörd-with-emoji-🔐",
        "アカウント 🎉",
        "Notes with عربى script and \"quotes\"",
    )];

    let blob = build_v31_shape_with_sentinel("33", entries);
    let outcome = production_pipeline()
        .decrypt_string(&blob, &password())
        .unwrap();
    let e = &outcome.entries.entries()[0];
    assert_eq!(e.url.as_str(), "https://accounts.example.中国");
    assert_eq!(e.username.as_str(), "user.李四@example.com");
    assert_eq!(e.password.as_str(), "P@sswörd-with-emoji-🔐");
    assert_eq!(e.name.as_str(), "アカウント 🎉");
    assert_eq!(e.note.as_str(), "Notes with عربى script and \"quotes\"");
}

#[test]
fn lenient_round_trips_android_uri_entries() {
    // Android-app entries use `android://com.bundle.id` URLs; the lenient
    // path must not strip or mangle them.
    let entries = vec![
        TestEntry::new(
            "android://com.samsung.android.app.samsungpay",
            "user@example.com",
            "SamsungPay!",
            "Samsung Pay",
            "",
        ),
        TestEntry::new(
            "android://com.netflix.mediaclient",
            "user@example.com",
            "Netflix!",
            "Netflix App",
            "",
        ),
    ];

    let blob = build_v31_shape_with_sentinel("33", entries);
    let outcome = production_pipeline()
        .decrypt_string(&blob, &password())
        .unwrap();
    let entries = outcome.entries.entries();
    assert!(entries[0].url.as_str().starts_with("android://com.samsung"));
    assert!(entries[1].url.as_str().starts_with("android://com.netflix"));
}

#[test]
fn lenient_round_trips_long_field_values() {
    // 4 KB password (synthetic, but valid). Confirms Base64 + UTF-8 path
    // handles large per-cell payloads without truncation.
    let long_password: String = "Ab1!".repeat(1024); // 4096 chars
    let entries = vec![TestEntry::new(
        "https://example.com/very/long/path".to_string(),
        "user@example.com".to_string(),
        long_password.clone(),
        "Example".to_string(),
        "".to_string(),
    )];

    let blob = build_v31_shape_with_sentinel("33", entries);
    let outcome = production_pipeline()
        .decrypt_string(&blob, &password())
        .unwrap();
    assert_eq!(
        outcome.entries.entries()[0].password.as_str(),
        long_password
    );
}

#[test]
fn lenient_round_trips_empty_note_via_absent_sentinel() {
    // Samsung writes the absent-value sentinel (`&&&NULL&&&`) for fields the
    // user didn't fill in. The lenient parser must collapse that to an
    // empty string on the way out, same as the strict v31 parser does.
    let entries = vec![TestEntry::new(
        "https://example.com",
        "user@example.com",
        "Password!1",
        "Example",
        "", // testkit emits absent sentinel for empty notes on v31
    )];

    let blob = build_v31_shape_with_sentinel("33", entries);
    let outcome = production_pipeline()
        .decrypt_string(&blob, &password())
        .unwrap();
    assert_eq!(outcome.entries.entries()[0].note.as_str(), "");
}

// =============================================================================
// Section 6: pipeline-level interaction tests
// =============================================================================

#[test]
fn wrong_password_on_unknown_version_fails_at_crypto_layer() {
    // Version detection runs after AES, so wrong-password on an unknown-
    // version file is still a Decryption error, not UnknownVersion. Confirms
    // we don't accidentally leak the sentinel through the wrong-password
    // error path.
    let blob = build_v31_shape_with_sentinel("33", sample_entries());
    let err = production_pipeline()
        .decrypt_string(&blob, &EntryPassword::new("WrongPassword".into()))
        .unwrap_err();
    match err {
        SpassError::Decryption(_) => {}
        SpassError::UnknownVersionUnparseable(_) => {
            panic!("wrong-password must not surface the unknown-version diagnostic")
        }
        other => panic!("expected Decryption error, got {other:?}"),
    }
}

#[test]
fn unknown_version_with_zero_entries_succeeds_with_empty_collection() {
    // Lenient is more forgiving than strict v31, which errors with "no
    // entries". An empty BestEffort file -- e.g. a brand-new Samsung
    // account with nothing exported yet -- should still parse cleanly so
    // the consumer can show an "all good but nothing to import" state.
    let blob = build_v31_shape_with_sentinel("33", Vec::new());
    let outcome = production_pipeline()
        .decrypt_string(&blob, &password())
        .unwrap();
    assert_eq!(outcome.entries.len(), 0);
    if let VersionStatus::BestEffort { report } = outcome.version_status {
        assert_eq!(report.entries_extracted, 0);
        assert!(report.missing_required_columns.is_empty());
    } else {
        panic!("expected BestEffort");
    }
}

#[test]
fn besteffort_doesnt_validate_version_specific_marker_line() {
    // Strict v30 expects `next_table` on line 3; strict v31 on line 4. The
    // lenient path doesn't know which line index a future version puts it
    // on, so the marker check is skipped -- the lenient parser detects the
    // boundary by searching for the literal `next_table` string. This test
    // confirms that skip by constructing a file whose `next_table` lives
    // somewhere that NEITHER strict path would accept: line 5.
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

    let canonical_header = SpassGenerator::canonical_v31_header().join(";");
    let row = {
        let mut parts: Vec<String> = (0..35).map(|_| String::new()).collect();
        parts[1] = BASE64.encode("https://example.com");
        parts[4] = BASE64.encode("user@example.com");
        parts[7] = BASE64.encode("password!");
        parts[17] = BASE64.encode("Example");
        parts[31] = BASE64.encode("&&&NULL&&&");
        parts.join(";")
    };

    // Sentinel + 4 metadata lines + next_table + header + row. This is
    // line 6 (1-indexed) for next_table, breaking both v30 (line 3) and
    // v31 (line 4) expectations.
    let plaintext = format!(
        "future-version\nflag_a\nflag_b\nflag_c\nflag_d\nnext_table\n{canonical_header}\n{row}\n"
    );

    // Hand-encrypt with the same dance the testkit uses internally.
    use aes::Aes256;
    use cbc::cipher::generic_array::GenericArray;
    use cbc::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
    use cbc::Encryptor;
    use hmac::Hmac;
    use pbkdf2::pbkdf2;
    use sha2::Sha256;

    let salt = [0xab_u8; 20];
    let iv = [0xcd_u8; 16];
    let mut key = [0u8; 32];
    pbkdf2::<Hmac<Sha256>>(TEST_PASSWORD.as_bytes(), &salt, 70_000, &mut key).unwrap();
    let mut buffer = plaintext.as_bytes().to_vec();
    buffer.resize(plaintext.len() + 16, 0);
    let encryptor = Encryptor::<Aes256>::new(
        GenericArray::from_slice(&key),
        GenericArray::from_slice(&iv),
    );
    let len = encryptor
        .encrypt_padded_mut::<Pkcs7>(&mut buffer, plaintext.len())
        .unwrap()
        .len();
    buffer.truncate(len);

    let mut blob = Vec::with_capacity(36 + buffer.len());
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&iv);
    blob.extend_from_slice(&buffer);
    let encoded = BASE64.encode(&blob);

    let outcome = production_pipeline()
        .decrypt_string(&encoded, &password())
        .unwrap();
    assert_eq!(outcome.entries.len(), 1);
    if let VersionStatus::BestEffort { report } = outcome.version_status {
        assert_eq!(report.sentinel, "future-version");
        assert_eq!(report.entries_extracted, 1);
    } else {
        panic!("expected BestEffort");
    }
}
