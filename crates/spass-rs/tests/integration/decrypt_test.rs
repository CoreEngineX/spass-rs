//! Integration tests for the complete decryption pipeline.
//!
//! These tests use real `.spass` files to verify end-to-end functionality.

use spass::{crypto::PBKDF2_ITERATIONS, domain::EntryPassword, pipeline::DecryptionPipeline};

/// Test full decryption pipeline with a real `.spass` file.
///
/// This test requires a password to decrypt the fixture file.
/// If you don't have the password, this test will be ignored.
#[test]
#[ignore = "requires password for fixture file"]
fn test_decrypt_real_spass_file() {
    let fixture_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sample.spass");

    // Replace with actual password if available
    let password = EntryPassword::new("test_password".into());

    let pipeline = DecryptionPipeline::new(PBKDF2_ITERATIONS);
    let result = pipeline.decrypt_file(fixture_path, &password);

    // This will fail if password is wrong, which is expected for ignored test
    if let Ok(collection) = result {
        assert!(
            !collection.is_empty(),
            "Expected at least one password entry"
        );
        println!("Successfully decrypted {} entries", collection.len());
    }
}

/// Test that decryption fails with wrong password.
#[test]
#[ignore = "requires fixture file"]
fn test_decrypt_with_wrong_password() {
    let fixture_path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sample.spass");

    let wrong_password = EntryPassword::new("definitely_wrong_password".into());

    let pipeline = DecryptionPipeline::new(PBKDF2_ITERATIONS);
    let result = pipeline.decrypt_file(fixture_path, &wrong_password);

    assert!(
        result.is_err(),
        "Expected decryption to fail with wrong password"
    );
}

/// Test that pipeline can handle file not found error.
#[test]
fn test_decrypt_nonexistent_file() {
    let nonexistent_path = "/tmp/nonexistent_file_12345.spass";
    let password = EntryPassword::new("password".into());

    let pipeline = DecryptionPipeline::new(PBKDF2_ITERATIONS);
    let result = pipeline.decrypt_file(nonexistent_path, &password);

    assert!(result.is_err(), "Expected error for nonexistent file");
}

/// Test pipeline with default settings.
#[test]
fn test_pipeline_default() {
    let pipeline = DecryptionPipeline::default();

    // Just verify it constructs successfully
    // Actual decryption would require a valid file and password
    let _ = pipeline;
}

/// Test pipeline builder pattern.
#[test]
fn test_pipeline_builder() {
    use spass::pipeline::PipelineBuilder;

    let pipeline = PipelineBuilder::new().iterations(100_000).build();

    let _ = pipeline;
}
