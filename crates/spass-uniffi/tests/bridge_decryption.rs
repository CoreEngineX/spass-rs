//! Integration tests for the FFI bridge: the real `extern "C"` functions, called as the apps call
//! them, with the status and errors lifted the way the generated bindings lift them.
//!
//! Fixtures are generated in-process via `spass::testkit` so the tests are self-contained. They do
//! not depend on any files in the workspace's `tmp/` directory, which is gitignored and not
//! present on CI runners.

use std::ptr;

use spass::EntryBuffer;
use spass::format::SpassFormatVersion;
use spass::testkit::{SpassGenerator, TestEntry};
use spass_uniffi::entries::{
    SPASS_ENTRIES_FAILED, SPASS_ENTRIES_HANDED_OVER, SPASS_ENTRIES_PANICKED, SpassEntries,
    spass_decrypt_entries,
};
use spass_uniffi::{
    ENTRIES_ABI_VERSION, FfiVersionStatus, SpassFfiError, UniFfiTag, entries_abi_version,
};
use uniffi::RustBuffer;

const TEST_PASSWORD: &str = "TestPassword123";
const UTF8_BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];

/// What one call to `spass_decrypt_entries` gave back.
enum Called {
    Entries {
        entries: EntryBuffer,
        status: FfiVersionStatus,
    },
    Failed(SpassFfiError),
    Panicked,
}

/// Calls `spass_decrypt_entries` with `file` and `password` as given, null pointers for empty ones.
fn call_raw(file: &[u8], password: &[u8]) -> Called {
    let pointer = |bytes: &[u8]| {
        if bytes.is_empty() {
            ptr::null()
        } else {
            bytes.as_ptr()
        }
    };
    let mut out = SpassEntries {
        ptr: ptr::null_mut(),
        len: 0,
        cap: 0,
        count: 0,
        index_offset: 0,
    };
    let mut status = RustBuffer::new();

    // SAFETY: the inputs are valid for their lengths (null only when empty), and `out` and
    // `status` are valid for writes.
    let code = unsafe {
        spass_decrypt_entries(
            pointer(file),
            file.len(),
            pointer(password),
            password.len(),
            &raw mut out,
            &raw mut status,
        )
    };

    match code {
        SPASS_ENTRIES_HANDED_OVER => Called::Entries {
            // SAFETY: `out` was written by `spass_decrypt_entries` and is taken once.
            entries: unsafe { EntryBuffer::from_raw_parts(out) },
            status: <FfiVersionStatus as uniffi::Lift<UniFfiTag>>::try_lift_from_rust_buffer(
                status,
            )
            .expect("a lowered status lifts"),
        },
        SPASS_ENTRIES_FAILED => Called::Failed(
            <SpassFfiError as uniffi::Lift<UniFfiTag>>::try_lift_from_rust_buffer(status)
                .expect("a lowered error lifts"),
        ),
        SPASS_ENTRIES_PANICKED => Called::Panicked,
        other => panic!("unknown status code {other}"),
    }
}

fn call(file: &str, password: &str) -> Called {
    call_raw(file.as_bytes(), password.as_bytes())
}

fn entries_of(called: Called) -> (EntryBuffer, FfiVersionStatus) {
    match called {
        Called::Entries { entries, status } => (entries, status),
        Called::Failed(error) => panic!("expected entries, got {error:?}"),
        Called::Panicked => panic!("expected entries, the call panicked"),
    }
}

fn error_of(called: Called) -> SpassFfiError {
    match called {
        Called::Failed(error) => error,
        Called::Entries { entries, .. } => {
            panic!("expected an error, got {} entries", entries.len())
        }
        Called::Panicked => panic!("expected an error, the call panicked"),
    }
}

fn numbered(n: usize) -> Vec<TestEntry> {
    (0..n)
        .map(|i| {
            TestEntry::new(
                format!("https://example{i}.com"),
                format!("user{i}@example.com"),
                format!("password{i}"),
                format!("Site {i}"),
                "",
            )
        })
        .collect()
}

fn fixture_with_n_entries(n: usize, password: &str) -> String {
    SpassGenerator::new(password)
        .entries(numbered(n))
        .generate()
}

fn v31_fixture_with_n_entries(n: usize, password: &str) -> String {
    SpassGenerator::new(password)
        .with_version(SpassFormatVersion::V31)
        .entries(numbered(n))
        .generate()
}

fn fields(entries: &EntryBuffer, index: usize) -> [String; 5] {
    let entry = entries.get(index).expect("entry exists");
    [
        entry.url,
        entry.username,
        entry.password,
        entry.name,
        entry.note,
    ]
    .map(str::to_owned)
}

fn known_version(status: &FfiVersionStatus) -> &str {
    match status {
        FfiVersionStatus::Known { version } => version,
        FfiVersionStatus::BestEffort { .. } => panic!("expected Known, got {status:?}"),
    }
}

#[test]
fn the_abi_version_is_the_one_in_the_header() {
    assert_eq!(entries_abi_version(), ENTRIES_ABI_VERSION);
    assert_eq!(ENTRIES_ABI_VERSION, 1);
}

#[test]
fn decrypts_one_entry_fixture() {
    let (entries, status) = entries_of(call(
        &fixture_with_n_entries(1, TEST_PASSWORD),
        TEST_PASSWORD,
    ));

    assert_eq!(entries.len(), 1);
    assert_eq!(known_version(&status), "V30");
}

#[test]
fn decrypts_multi_entry_fixture() {
    let (entries, _) = entries_of(call(
        &fixture_with_n_entries(8, TEST_PASSWORD),
        TEST_PASSWORD,
    ));

    assert_eq!(entries.len(), 8);
    assert_eq!(fields(&entries, 7)[0], "https://example7.com");
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

    let (entries, _) = entries_of(call(&spass, TEST_PASSWORD));

    assert_eq!(
        fields(&entries, 0),
        [
            "https://example.com",
            "alice@example.com",
            "alicePassword!",
            "Example Account",
            "Test note"
        ]
    );
}

#[test]
fn zero_entry_v30_fixture_is_invalid_format() {
    let error = error_of(call(
        &fixture_with_n_entries(0, TEST_PASSWORD),
        TEST_PASSWORD,
    ));

    assert!(
        matches!(error, SpassFfiError::InvalidFormat { .. }),
        "{error:?}"
    );
}

#[test]
fn zero_entry_v31_fixture_is_an_empty_buffer() {
    let (entries, status) = entries_of(call(
        &v31_fixture_with_n_entries(0, TEST_PASSWORD),
        TEST_PASSWORD,
    ));

    assert!(entries.is_empty());
    assert_eq!(known_version(&status), "V31");
}

#[test]
fn decrypts_v31_fixture() {
    let (entries, status) = entries_of(call(
        &v31_fixture_with_n_entries(5, TEST_PASSWORD),
        TEST_PASSWORD,
    ));

    assert_eq!(entries.len(), 5);
    assert_eq!(known_version(&status), "V31");
    assert_eq!(
        fields(&entries, 0),
        [
            "https://example0.com",
            "user0@example.com",
            "password0",
            "Site 0",
            ""
        ]
    );
}

#[test]
fn v31_field_mapping_round_trips() {
    // The v31 projection must pull from origin_url, username_value, password_value, title and
    // credential_memo, not username_element, password_element, app_name and the like.
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

    let (entries, _) = entries_of(call(&spass, TEST_PASSWORD));

    assert_eq!(
        fields(&entries, 0),
        [
            "android://com.example/login",
            "alice@example.com",
            "alicePassword!",
            "Example Account",
            "Test note"
        ]
    );
}

#[test]
fn special_characters_round_trip() {
    let spass = SpassGenerator::new(TEST_PASSWORD)
        .entry(TestEntry::new(
            "https://example.com/path?q=\"quoted\"",
            "user\\with\\backslashes",
            "p@ss\nwith\nnewlines",
            "Account \u{1f510}",
            "Note with \"quotes\" and a tab\tcharacter",
        ))
        .generate();

    let (entries, _) = entries_of(call(&spass, TEST_PASSWORD));

    assert_eq!(
        fields(&entries, 0),
        [
            "https://example.com/path?q=\"quoted\"",
            "user\\with\\backslashes",
            "p@ss\nwith\nnewlines",
            "Account \u{1f510}",
            "Note with \"quotes\" and a tab\tcharacter"
        ]
    );
}

#[test]
fn wrong_password_is_code_one_wrong_password() {
    let spass = fixture_with_n_entries(1, TEST_PASSWORD);

    let error = error_of(call(&spass, "DefinitelyWrongPassword"));

    assert!(matches!(error, SpassFfiError::WrongPassword), "{error:?}");
}

#[test]
fn wrong_password_on_a_v31_file_is_wrong_password() {
    let spass = v31_fixture_with_n_entries(3, TEST_PASSWORD);

    let error = error_of(call(&spass, "DefinitelyWrongPassword"));

    assert!(matches!(error, SpassFfiError::WrongPassword), "{error:?}");
}

#[test]
fn a_missing_required_column_is_unknown_version_with_the_report() {
    let header: Vec<&'static str> = SpassGenerator::canonical_v31_header()
        .into_iter()
        .filter(|name| *name != "password_value")
        .collect();
    let spass = SpassGenerator::new(TEST_PASSWORD)
        .with_version(SpassFormatVersion::V31)
        .with_v31_header(header)
        .entries(numbered(2))
        .generate();

    let error = error_of(call(&spass, TEST_PASSWORD));

    let SpassFfiError::UnknownVersion { report } = error else {
        panic!("expected UnknownVersion, got {error:?}");
    };
    assert_eq!(report.sentinel, "31");
    assert_eq!(report.missing_required_columns, ["password_value"]);
    assert_eq!(report.entries_extracted, 0);
}

/// Valid Base64 of zero bytes that decodes to a block-aligned ciphertext, 20 bytes longer than the
/// longest file the cap admits. Without the cap it would run PBKDF2 and AES and fail as
/// `WrongPassword`.
#[test]
fn a_file_over_the_cap_is_refused_before_decrypting() {
    let file = vec![b'A'; 139_810_224];

    let started = std::time::Instant::now();
    let error = error_of(call_raw(&file, TEST_PASSWORD.as_bytes()));

    assert!(
        matches!(error, SpassFfiError::InvalidFormat { .. }),
        "{error:?}"
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );
}

#[test]
fn a_leading_byte_order_mark_is_accepted() {
    let mut file = UTF8_BOM.to_vec();
    file.extend_from_slice(fixture_with_n_entries(2, TEST_PASSWORD).as_bytes());

    let (entries, _) = entries_of(call_raw(&file, TEST_PASSWORD.as_bytes()));

    assert_eq!(entries.len(), 2);
}

#[test]
fn a_null_file_with_zero_length_is_invalid_format() {
    let error = error_of(call_raw(&[], TEST_PASSWORD.as_bytes()));

    assert!(
        matches!(error, SpassFfiError::InvalidFormat { .. }),
        "{error:?}"
    );
}

#[test]
fn a_null_password_with_zero_length_is_the_empty_password() {
    let spass = fixture_with_n_entries(1, TEST_PASSWORD);

    let error = error_of(call_raw(spass.as_bytes(), &[]));

    assert!(
        matches!(
            error,
            SpassFfiError::WrongPassword | SpassFfiError::InvalidFormat { .. }
        ),
        "{error:?}"
    );
}

#[test]
fn a_password_that_is_not_utf8_is_invalid_format() {
    let spass = fixture_with_n_entries(1, TEST_PASSWORD);

    let error = error_of(call_raw(spass.as_bytes(), &[0xFF, 0xFE]));

    assert!(
        matches!(error, SpassFfiError::InvalidFormat { .. }),
        "{error:?}"
    );
}

#[test]
fn garbage_input_is_invalid_format() {
    let error = error_of(call("not-base64-not-anything", TEST_PASSWORD));

    assert!(
        matches!(error, SpassFfiError::InvalidFormat { .. }),
        "{error:?}"
    );
}

#[test]
fn best_effort_report_precomputes_ios_contribution_strings() {
    let file = SpassGenerator::new(TEST_PASSWORD)
        .with_version(SpassFormatVersion::V31)
        .with_sentinel("33")
        .entry(TestEntry::new(
            "https://example.com",
            "user@example.com",
            "password",
            "Site",
            "",
        ))
        .generate();

    let (entries, status) = entries_of(call(&file, TEST_PASSWORD));
    let FfiVersionStatus::BestEffort { report } = status else {
        panic!("expected BestEffort, got {status:?}");
    };

    // The bridge stamps its provenance from the target OS, so this test asserts against whichever
    // app it was compiled for. A host-target `cargo test` run takes the iOS arm, same as an iOS
    // device build.
    #[cfg(target_os = "android")]
    let (phrase, encoded) = (
        "Sent from the SPassPort Android app\n",
        "Sent%20from%20the%20SPassPort%20Android%20app",
    );
    #[cfg(not(target_os = "android"))]
    let (phrase, encoded) = (
        "Sent from the SPassPort iOS app\n",
        "Sent%20from%20the%20SPassPort%20iOS%20app",
    );

    assert_eq!(entries.len(), 1);
    assert_eq!(report.sentinel, "33");
    assert!(report.subject.contains("33"));
    assert!(
        report.body.ends_with(phrase),
        "body did not end with {phrase:?}"
    );
    assert!(report.github_issue_url.contains(encoded));
    assert!(report.mailto_url.contains(encoded));
}
