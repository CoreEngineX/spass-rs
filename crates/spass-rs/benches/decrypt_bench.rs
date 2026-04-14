//! Benchmarks for decryption operations.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use spass::crypto::{KeyDerivation, PBKDF2_ITERATIONS};
use spass::domain::EntryPassword;
use spass::format::SpassDecoder;

fn bench_key_derivation(c: &mut Criterion) {
    let kd = KeyDerivation::new(PBKDF2_ITERATIONS);
    let password = EntryPassword::new("benchmark_password".into());

    // Create a minimal valid base64-encoded spass structure for benchmarking
    let mut data = Vec::with_capacity(20 + 16);
    data.extend_from_slice(&[0u8; 20]); // salt
    data.extend_from_slice(&[0u8; 16]); // iv
    let base64_data = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &data);

    let decoder = SpassDecoder::new();
    let decoded = decoder.decode_from_string(&base64_data).unwrap();
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

    let decoder = SpassDecoder::new();
    let decoded = decoder.decode_from_string(&base64_data).unwrap();
    let salt = decoded.salt();

    let mut group = c.benchmark_group("key_derivation_iterations");

    for iterations in [10_000, 50_000, 70_000, 100_000].iter() {
        let kd = KeyDerivation::new(*iterations);
        group.bench_with_input(format!("{}_iterations", iterations), iterations, |b, _| {
            b.iter(|| {
                let _ = kd.derive_key(black_box(&password), black_box(salt));
            });
        });
    }

    group.finish();
}

fn bench_aes_decryption(c: &mut Criterion) {
    use spass::crypto::CipherEngine;

    let cipher = CipherEngine::new();
    let kd = KeyDerivation::new(1000); // Low iterations for faster setup

    // Create encrypted data for benchmarking
    let password = EntryPassword::new("benchmark_password".into());
    let ciphertext_bytes = [0u8; 256]; // 256 bytes

    // Create a valid base64-encoded spass structure with ciphertext
    let mut data = Vec::with_capacity(20 + 16 + 256);
    data.extend_from_slice(&[0u8; 20]); // salt
    data.extend_from_slice(&[0u8; 16]); // iv
    data.extend_from_slice(&ciphertext_bytes); // ciphertext
    let base64_data = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &data);

    let decoder = SpassDecoder::new();
    let decoded = decoder.decode_from_string(&base64_data).unwrap();

    let key = kd.derive_key(&password, decoded.salt()).unwrap();

    c.bench_function("aes256_cbc_decrypt_256_bytes", |b| {
        b.iter(|| {
            let _ = cipher.decrypt(
                black_box(decoded.ciphertext()),
                black_box(&key),
                black_box(decoded.iv()),
            );
        });
    });
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
            let _ = decoder.decode_from_string(black_box(&base64_encoded));
        });
    });
}

criterion_group!(
    benches,
    bench_key_derivation,
    bench_key_derivation_different_iterations,
    bench_aes_decryption,
    bench_base64_decode
);
criterion_main!(benches);
