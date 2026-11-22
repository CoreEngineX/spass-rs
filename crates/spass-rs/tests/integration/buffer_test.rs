//! `decrypt_to_buffer` against the collection decoder in `spass::testkit::oracle`, field for field,
//! on every fixture under `gen-test/`, and the buffer layout read back without `EntryBuffer`.
//!
//! The large stress fixtures are gitignored; a test skips with a note when its file is absent.

use std::collections::BTreeSet;
use std::mem::discriminant;
use std::path::{Path, PathBuf};

use spass::EntryBuffer;
use spass::crypto::PBKDF2_ITERATIONS;
use spass::domain::{EntryPassword, SpassError, VersionStatus};
use spass::pipeline::DecryptionPipeline;
use spass::testkit::oracle::{self, OracleEntry};

const PASSWORD: &str = "TestPassword123";
const GEN_TEST: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../gen-test");

/// Fixtures too large to commit, by path under `gen-test/`.
const LARGE: [&str; 5] = [
    "v31/stress-10k.spass",
    "v31/stress-100k.spass",
    "v31/stress-600k.spass",
    "v31/test05-1m.spass",
    "v30/test05-1m.spass",
];

/// Every `.spass` file in a subfolder of `gen-test/` that is not one of the large ones.
fn committed_fixtures() -> BTreeSet<PathBuf> {
    let mut fixtures = BTreeSet::new();
    for folder in std::fs::read_dir(GEN_TEST).expect("gen-test exists") {
        let folder = folder.expect("readable folder").path();
        if !folder.is_dir() {
            continue;
        }
        for file in std::fs::read_dir(&folder).expect("readable folder") {
            let file = file.expect("readable file").path();
            let relative = file.strip_prefix(GEN_TEST).expect("under gen-test");
            let large = relative.to_str().is_some_and(|name| LARGE.contains(&name));
            if file.extension().is_some_and(|ext| ext == "spass") && !large {
                fixtures.insert(file);
            }
        }
    }
    fixtures
}

fn same_status(new: &VersionStatus, old: &VersionStatus, label: &str) {
    match (new, old) {
        (VersionStatus::Known { version: new }, VersionStatus::Known { version: old }) => {
            assert_eq!(new, old, "{label}");
        }
        (VersionStatus::BestEffort { report: new }, VersionStatus::BestEffort { report: old }) => {
            assert_eq!(new, old, "{label}");
        }
        _ => panic!("{label}: version status differs: new {new:?}, old {old:?}"),
    }
}

fn same_entries(new: &EntryBuffer, old: Vec<OracleEntry>, label: &str) {
    assert_eq!(new.len(), old.len(), "{label}: entry count");
    for (index, (new, old)) in new.iter().zip(old).enumerate() {
        assert_eq!(
            [new.url, new.username, new.password, new.name, new.note],
            old.each_ref().map(String::as_str),
            "{label}: entry {index}"
        );
    }
}

/// Decrypts `path` both ways and requires the same entries and status, or the same error variant.
fn matches_the_collection_decoder(path: &Path) {
    let label = path.display().to_string();
    let file = std::fs::read(path).expect("fixture readable");

    let new = DecryptionPipeline::default()
        .decrypt_to_buffer(&file, &EntryPassword::new(PASSWORD.to_owned()));
    let old = oracle::decrypt(&file, PASSWORD, PBKDF2_ITERATIONS);
    drop(file);

    match (new, old) {
        (Ok(new), Ok((old_entries, old_status))) => {
            same_status(&new.version_status, &old_status, &label);
            same_entries(&new.entries, old_entries, &label);
        }
        (Err(new), Err(old)) => {
            assert_eq!(
                discriminant(&new),
                discriminant(&old),
                "{label}: new {new}, old {old}"
            );
            if let (
                SpassError::UnknownVersionUnparseable(new),
                SpassError::UnknownVersionUnparseable(old),
            ) = (&new, &old)
            {
                assert_eq!(new, old, "{label}");
            }
        }
        (Ok(_), Err(old)) => panic!("{label}: new decrypted, old failed: {old}"),
        (Err(new), Ok(_)) => panic!("{label}: new failed: {new}, old decrypted"),
    }
}

#[test]
fn every_committed_fixture_matches_the_collection_decoder() {
    let fixtures = committed_fixtures();
    assert!(!fixtures.is_empty(), "no fixtures under {GEN_TEST}");

    for path in fixtures {
        matches_the_collection_decoder(&path);
    }
}

fn large_fixture(name: &str) {
    let path = Path::new(GEN_TEST).join(name);
    if path.exists() {
        matches_the_collection_decoder(&path);
    } else {
        eprintln!("skipping {name}: not present");
    }
}

#[test]
fn stress_10k_v31_matches_the_collection_decoder() {
    large_fixture("v31/stress-10k.spass");
}

#[test]
fn stress_100k_v31_matches_the_collection_decoder() {
    large_fixture("v31/stress-100k.spass");
}

#[test]
fn stress_600k_v31_matches_the_collection_decoder() {
    large_fixture("v31/stress-600k.spass");
}

/// Over the plaintext ceiling: both decoders refuse it, with the same variant.
#[test]
fn one_million_v31_fails_both_ways() {
    large_fixture("v31/test05-1m.spass");
}

#[test]
fn one_million_v30_matches_the_collection_decoder() {
    large_fixture("v30/test05-1m.spass");
}

#[test]
fn decrypt_file_and_decrypt_to_buffer_agree() {
    let path = Path::new(GEN_TEST).join("v31/test03-medium.spass");
    let pipeline = DecryptionPipeline::default();
    let password = EntryPassword::new(PASSWORD.to_owned());

    let from_file = pipeline.decrypt_file(&path, &password).unwrap();
    let from_bytes = pipeline
        .decrypt_to_buffer(&std::fs::read(&path).unwrap(), &password)
        .unwrap();

    assert_eq!(from_file.entries.as_bytes(), from_bytes.entries.as_bytes());
}

fn word(bytes: &[u8], at: usize) -> usize {
    let word: [u8; 4] = bytes[at..at + 4].try_into().expect("four bytes");
    usize::try_from(u32::from_le_bytes(word)).expect("fits")
}

/// The layout in the contract, read with nothing but the bytes: fields in slot order, zero padding
/// to a multiple of four, five little-endian `u32` end offsets per entry.
#[test]
fn the_buffer_has_the_documented_layout() {
    for name in ["v30/test03-medium.spass", "v31/test03-medium.spass"] {
        let path = Path::new(GEN_TEST).join(name);
        let outcome = DecryptionPipeline::default()
            .decrypt_file(&path, &EntryPassword::new(PASSWORD.to_owned()))
            .unwrap();
        let bytes = outcome.entries.as_bytes();
        let count = outcome.entries.len();
        let index_offset = outcome.entries.index_offset();

        assert!(count > 0, "{name}");
        assert_eq!(index_offset % 4, 0, "{name}");
        assert_eq!(bytes.len(), index_offset + 20 * count, "{name}");
        let fields_end = word(bytes, bytes.len() - 4);
        assert!(index_offset - fields_end < 4, "{name}");
        assert!(
            bytes[fields_end..index_offset]
                .iter()
                .all(|&byte| byte == 0),
            "{name}"
        );

        let mut start = 0;
        for (index, entry) in outcome.entries.iter().enumerate() {
            let mut fields = [""; 5];
            for (slot, field) in fields.iter_mut().enumerate() {
                let end = word(bytes, index_offset + 20 * index + 4 * slot);
                assert!(end >= start, "{name}: entry {index} slot {slot}");
                *field = std::str::from_utf8(&bytes[start..end]).expect("a field is UTF-8");
                start = end;
            }
            assert_eq!(
                fields,
                [
                    entry.url,
                    entry.username,
                    entry.password,
                    entry.name,
                    entry.note
                ],
                "{name}: entry {index}"
            );
        }
        assert_eq!(start, fields_end, "{name}");
    }
}
