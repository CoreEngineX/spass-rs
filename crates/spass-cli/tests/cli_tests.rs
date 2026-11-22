//! CLI integration tests.

use predicates::prelude::*;
use spass::format::SpassFormatVersion;
use spass::testkit::{SpassGenerator, TestEntry};
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

const PASSWORD: &str = "cli-test-password";
const ITERATIONS: NonZeroU32 = NonZeroU32::new(1_000).unwrap();

const EXPECTED_CSV: &str = "\
name,url,username,password,note
Example,https://example.com,ann@example.com,pw-one,
\"Comma, and \"\"quote\"\"\",,bob,\"p,w \"\"two\"\"\",\"line one
line two\"
Ünïcode 日本,android://abc,cy,pw-three,plain note
";

const EXPECTED_JSON: &str = r#"[
  {
    "name": "Example",
    "url": "https://example.com",
    "username": "ann@example.com",
    "password": "pw-one",
    "note": ""
  },
  {
    "name": "Comma, and \"quote\"",
    "url": "",
    "username": "bob",
    "password": "p,w \"two\"",
    "note": "line one\nline two"
  },
  {
    "name": "Ünïcode 日本",
    "url": "android://abc",
    "username": "cy",
    "password": "pw-three",
    "note": "plain note"
  }
]"#;

struct Scratch(PathBuf);

impl Scratch {
    fn new(test: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("spass-cli-{test}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn fixture(scratch: &Scratch, version: SpassFormatVersion) -> PathBuf {
    let entries = [
        TestEntry::new(
            "https://example.com",
            "ann@example.com",
            "pw-one",
            "Example",
            "",
        ),
        TestEntry::new(
            "",
            "bob",
            "p,w \"two\"",
            "Comma, and \"quote\"",
            "line one\nline two",
        ),
        TestEntry::new(
            "android://abc",
            "cy",
            "pw-three",
            "Ünïcode 日本",
            "plain note",
        ),
    ];
    let text = SpassGenerator::new(PASSWORD)
        .with_version(version)
        .entries(entries)
        .generate_with_iterations(ITERATIONS);
    let path = scratch.path("fixture.spass");
    std::fs::write(&path, text).unwrap();
    path
}

fn decrypt(input: &Path) -> assert_cmd::Command {
    let mut cmd = assert_cmd::cargo_bin_cmd!("spass");
    cmd.arg("decrypt")
        .arg(input)
        .args(["--password", PASSWORD, "--no-progress"])
        .args(["--iterations", &ITERATIONS.to_string()])
        .env("NO_COLOR", "1");
    cmd
}

#[test]
fn test_help_command() {
    let mut cmd = assert_cmd::cargo_bin_cmd!("spass");

    cmd.arg("--help");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Samsung Pass Decryptor"))
        .stdout(predicate::str::contains("decrypt"))
        .stdout(predicate::str::contains("info"));
}

#[test]
fn test_version_command() {
    let mut cmd = assert_cmd::cargo_bin_cmd!("spass");

    cmd.arg("--version");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn test_decrypt_help() {
    let mut cmd = assert_cmd::cargo_bin_cmd!("spass");

    cmd.arg("decrypt").arg("--help");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Decrypt a .spass file"))
        .stdout(predicate::str::contains("--output"))
        .stdout(predicate::str::contains("--password"))
        .stdout(predicate::str::contains("--format"));
}

#[test]
fn test_info_help() {
    let mut cmd = assert_cmd::cargo_bin_cmd!("spass");

    cmd.arg("info").arg("--help");

    cmd.assert().success().stdout(predicate::str::contains(
        "Show information about a .spass file",
    ));
}

#[test]
fn test_decrypt_missing_file() {
    let mut cmd = assert_cmd::cargo_bin_cmd!("spass");

    cmd.arg("decrypt")
        .arg("nonexistent_file.spass")
        .arg("--password")
        .arg("test");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Error"));
}

#[test]
fn test_decrypt_invalid_format() {
    let mut cmd = assert_cmd::cargo_bin_cmd!("spass");

    cmd.arg("decrypt")
        .arg("test.spass")
        .arg("--format")
        .arg("invalid_format")
        .arg("--password")
        .arg("test");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("possible values: csv, json"));
}

#[test]
fn test_info_missing_file() {
    let mut cmd = assert_cmd::cargo_bin_cmd!("spass");

    cmd.arg("info").arg("nonexistent_file.spass");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Error"));
}

#[test]
fn a_v30_fixture_decrypts_to_the_exact_csv() {
    let scratch = Scratch::new("csv");
    let input = fixture(&scratch, SpassFormatVersion::V30);
    let output = scratch.path("out.csv");

    decrypt(&input)
        .arg("--output")
        .arg(&output)
        .assert()
        .success();

    assert_eq!(std::fs::read_to_string(output).unwrap(), EXPECTED_CSV);
}

#[test]
fn a_v31_fixture_decrypts_to_the_exact_json() {
    let scratch = Scratch::new("json");
    let input = fixture(&scratch, SpassFormatVersion::V31);
    let output = scratch.path("out.json");

    decrypt(&input)
        .args(["--format", "json"])
        .arg("--output")
        .arg(&output)
        .assert()
        .success();

    assert_eq!(std::fs::read_to_string(output).unwrap(), EXPECTED_JSON);
}

#[test]
fn a_v31_fixture_decrypts_to_the_same_csv_as_v30() {
    let scratch = Scratch::new("csv-v31");
    let input = fixture(&scratch, SpassFormatVersion::V31);
    let output = scratch.path("out.csv");

    decrypt(&input)
        .arg("--output")
        .arg(&output)
        .assert()
        .success();

    assert_eq!(std::fs::read_to_string(output).unwrap(), EXPECTED_CSV);
}

#[test]
fn the_summary_counts_entries_and_entries_with_a_url() {
    let scratch = Scratch::new("summary");
    let input = fixture(&scratch, SpassFormatVersion::V30);
    let output = scratch.path("out.csv");

    decrypt(&input)
        .arg("--output")
        .arg(&output)
        .assert()
        .success()
        .stdout(predicate::str::contains("Decrypted: 3"))
        .stdout(predicate::str::contains("Websites: 2 with URLs"));
}

#[test]
fn an_output_path_that_cannot_be_created_exits_with_an_output_error() {
    let scratch = Scratch::new("unwritable");
    let input = fixture(&scratch, SpassFormatVersion::V30);
    let output = scratch.path("missing-directory").join("out.csv");

    decrypt(&input)
        .arg("--output")
        .arg(&output)
        .assert()
        .code(1)
        .stderr(predicate::str::contains("Failed to write output"));
}

#[cfg(target_os = "linux")]
#[test]
fn an_output_that_fails_while_writing_exits_with_an_output_error() {
    let scratch = Scratch::new("full");
    let input = fixture(&scratch, SpassFormatVersion::V30);

    decrypt(&input)
        .args(["--output", "/dev/full"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("Failed to write output"));
}
