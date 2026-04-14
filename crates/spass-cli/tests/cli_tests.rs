//! CLI integration tests.

use predicates::prelude::*;

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
        .stdout(predicate::str::contains("0.2"));
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
        .stderr(predicate::str::contains("Invalid format"));
}

#[test]
fn test_info_missing_file() {
    let mut cmd = assert_cmd::cargo_bin_cmd!("spass");

    cmd.arg("info").arg("nonexistent_file.spass");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Error"));
}
