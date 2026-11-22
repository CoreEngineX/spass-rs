//! Benchmarks for decryption operations.

use criterion::{Criterion, criterion_group, criterion_main};
use spass::crypto::{KeyDerivation, PBKDF2_ITERATIONS};
use spass::domain::EntryPassword;
use spass::format::{SpassDecoder, SpassFormatVersion};
use spass::pipeline::PipelineBuilder;
use spass::testkit::{SpassGenerator, TestEntry};
use std::hint::black_box;
use std::num::NonZeroU32;

fn bench_key_derivation(c: &mut Criterion) {
    let kd = KeyDerivation::new(PBKDF2_ITERATIONS);
    let password = EntryPassword::new("benchmark_password".into());

    // Create a minimal valid base64-encoded spass structure for benchmarking
    let mut data = Vec::with_capacity(20 + 16);
    data.extend_from_slice(&[0u8; 20]); // salt
    data.extend_from_slice(&[0u8; 16]); // iv
    let base64_data = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &data);

    let decoded = SpassDecoder::new()
        .decode_from_bytes(base64_data.as_bytes())
        .unwrap();
    let salt = decoded.salt();

    c.bench_function("key_derivation_70k_iterations", |b| {
        b.iter(|| {
            let _ = kd.derive_key(black_box(&password), black_box(salt));
        });
    });
}

fn bench_key_derivation_different_iterations(c: &mut Criterion) {
    let password = EntryPassword::new("benchmark_password".into());

    // Create a minimal valid base64-encoded spass structure
    let mut data = Vec::with_capacity(20 + 16);
    data.extend_from_slice(&[0u8; 20]); // salt
    data.extend_from_slice(&[0u8; 16]); // iv
    let base64_data = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &data);

    let decoded = SpassDecoder::new()
        .decode_from_bytes(base64_data.as_bytes())
        .unwrap();
    let salt = decoded.salt();

    let mut group = c.benchmark_group("key_derivation_iterations");

    for iterations in [10_000, 50_000, 70_000, 100_000].map(|n| NonZeroU32::new(n).unwrap()) {
        let kd = KeyDerivation::new(iterations);
        group.bench_with_input(format!("{iterations}_iterations"), &iterations, |b, _| {
            b.iter(|| {
                let _ = kd.derive_key(black_box(&password), black_box(salt));
            });
        });
    }

    group.finish();
}

fn bench_decrypt_to_buffer(c: &mut Criterion) {
    const ITERATIONS: NonZeroU32 = NonZeroU32::new(1_000).unwrap();
    const ENTRIES: usize = 10_000;

    let password = EntryPassword::new("benchmark_password".into());
    let pipeline = PipelineBuilder::new().iterations(ITERATIONS).build();

    let mut group = c.benchmark_group("decrypt_to_buffer_10k_entries");
    for (name, version) in [
        ("v30", SpassFormatVersion::V30),
        ("v31", SpassFormatVersion::V31),
    ] {
        let entries = (0..ENTRIES).map(|i| {
            TestEntry::new(
                format!("https://example{i}.com"),
                format!("user{i}@example.com"),
                format!("P@ss#{i:07}!Sec"),
                format!("Account {i:07}"),
                if i % 5 == 0 {
                    format!("note {i}")
                } else {
                    String::new()
                },
            )
        });
        let file = SpassGenerator::new("benchmark_password")
            .with_version(version)
            .entries(entries)
            .generate_with_iterations(ITERATIONS);

        group.bench_function(name, |b| {
            b.iter(|| {
                pipeline
                    .decrypt_to_buffer(black_box(file.as_bytes()), black_box(&password))
                    .unwrap()
            });
        });
    }
    group.finish();
}

fn bench_base64_decode(c: &mut Criterion) {
    // Create a small base64-encoded sample
    let sample_data = vec![0u8; 1024]; // 1KB of zeros
    let mut encoded = Vec::with_capacity(20 + 16 + 1024);
    encoded.extend_from_slice(&[0u8; 20]); // salt
    encoded.extend_from_slice(&[0u8; 16]); // iv
    encoded.extend_from_slice(&sample_data); // ciphertext

    let base64_encoded =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &encoded);

    let decoder = SpassDecoder::new();

    c.bench_function("base64_decode_1kb", |b| {
        b.iter(|| {
            let _ = decoder.decode_from_bytes(black_box(base64_encoded.as_bytes()));
        });
    });
}

criterion_group!(
    benches,
    bench_key_derivation,
    bench_key_derivation_different_iterations,
    bench_decrypt_to_buffer,
    bench_base64_decode
);
criterion_main!(benches);
