# spass-core

A secure, type-safe Rust library and toolchain for decrypting Samsung Pass (`.spass`) export files and converting them to CSV or JSON.

## Problem

Samsung Pass only exports passwords as encrypted `.spass` files that restore on other Samsung devices. That makes it impossible to migrate to Apple Passwords, Chrome, Bitwarden, or any other manager.

`spass-core` decrypts those files and converts them to portable formats every password manager can import. It ships as a library, a CLI, and FFI-friendly bindings for native and web apps.

## Features

- AES-256-CBC decryption with PBKDF2-HMAC-SHA256 (70,000 iterations)
- Both known Samsung Pass plaintext formats supported: **V3.0** (`spass_export_v1` line-1 sentinel) and **V3.1** (`31` sentinel)
- CSV and JSON export
- Interactive CLI with password prompting, progress bars, and coloured output
- File inspection -- view `.spass` structure without decrypting
- Sensitive data zeroized on drop
- Constant-time error handling to prevent timing side-channels
- Hardware AES + SHA-2 acceleration auto-detected on host builds (see Hardware crypto below for cross-compile guidance)
- CI: fmt, clippy, tests, doctests, doc, and `cargo audit` on every push

## Workspace layout

```
crates/
  spass-rs/        Core library -- pure Rust, no FFI. Published to crates.io as `spass`.
  spass-cli/       Command-line binary built on top of spass-rs.
  spass-uniffi/    Swift bindings via UniFFI. Build into a static library + `.swift`
                   files; drop into any iOS / macOS / visionOS app target.
  spass-wasm/      wasm-bindgen wrapper compiled to `wasm32-unknown-unknown`. Build with
                   `wasm-pack` and drop the resulting `pkg/` into any browser app.
```

All three boundary crates (`spass-cli`, `spass-uniffi`, `spass-wasm`) depend on `spass-rs` and only translate at the boundary. New format / pipeline logic lands in `spass-rs` first; the boundaries follow.

## Library usage

```toml
[dependencies]
spass = "0.2"
```

```rust
use spass::pipeline::DecryptionPipeline;
use spass::domain::EntryPassword;

let pipeline = DecryptionPipeline::default();
let password = EntryPassword::new("my_password".to_string());
let collection = pipeline.decrypt_file("passwords.spass", &password)?;

for entry in collection {
    println!("{}: {}", entry.name(), entry.username());
}
```

`DecryptionPipeline::default()` uses the canonical `PBKDF2_ITERATIONS` constant (70 000). Pass `DecryptionPipeline::new(N)` to test with a lower iteration count in benchmarks.

## CLI

### Installation

```bash
cargo install --git https://github.com/CoreEngineX/spass-rs spass-cli
```

### Usage

```bash
# Interactive -- prompts for password (recommended)
spass decrypt passwords.spass -o output.csv

# Export as JSON
spass decrypt passwords.spass -f json -o output.json

# Write to stdout
spass decrypt passwords.spass > output.csv

# Inspect a file without decrypting (header + version + entry count)
spass info passwords.spass

# Generate a synthetic fixture for benchmarking (writes to gen-test/v30/)
cargo test -p spass generate_1m_fixture -- --nocapture --ignored
```

## Native bindings (Swift / iOS / macOS)

`spass-uniffi` exposes the decrypt pipeline through [UniFFI](https://github.com/mozilla/uniffi-rs). Build it as a static library, drop the generated `.swift` file into your app target, and call the pipeline from Swift like any other library.

Quick build (single iOS arch, simulator):

```bash
cargo build -p spass-uniffi --release \
  --target aarch64-apple-ios-sim
```

For shipping to a real iOS app you'll want a multi-arch `.xcframework` covering `aarch64-apple-ios` (device) and `aarch64-apple-ios-sim` (simulator) -- the standard UniFFI build flow handles that. Make sure to set the hardware crypto flags before building for iOS (see below).

The bindings return decrypted entries as a single JSON-encoded `String` rather than marshaling per-record structs. This minimizes FFI cost on large payloads (one Swift string allocation instead of N struct marshals); decode on the Swift side with `JSONDecoder` against a matching Swift struct.

## Web bindings (WebAssembly)

`spass-wasm` is a [wasm-bindgen](https://rustwasm.github.io/wasm-bindgen/) wrapper. Build with `wasm-pack`:

```bash
wasm-pack build crates/spass-wasm --target web --release
```

That produces a `pkg/` directory with a `.wasm` blob, a TS-typed JS shim, and the type definitions. Import it from any modern bundler (Next.js, Vite, etc.) and call the same decrypt entry point you'd hit from Swift -- the JSON-encoded-string return shape is identical.

There is no hardware crypto path in wasm; throughput is lower than native but well within interactive latency for typical file sizes.

## Format support

| Version | Status | Line-1 sentinel (in decrypted plaintext) |
|---|---|---|
| V3.0 | Supported | `spass_export_v1` -- the literal Samsung writes |
| V3.1 | Supported | `31` -- numeric |

`SpassFormatVersion::detect()` in `crates/spass-rs/src/format/version.rs` reads the first newline-terminated line of decrypted plaintext to dispatch. Adding a future V3.2 means a new variant + a new arm in `detect()`; consumers using the non-exhaustive enum will not break.

Note: historical versions of the in-tree testkit wrote the literal `30` for V3.0 fixtures. Real Samsung Pass V3.0 files write `spass_export_v1`. The library accepts the latter (matches real exports) and rejects the former (which was only ever in synthetic test fixtures). If you have an old test fixture failing with "Unsupported format version: 30", regenerate it from the current testkit.

## Hardware crypto

`spass-core` uses the `aes` and `sha2` crates, both of which dispatch to hardware instructions when available. The host (`cargo build` on M-series Macs or modern Intel/AMD) auto-detects this; **cross-compile targets do not**.

For iOS / Apple-Silicon targets, set:

```bash
RUSTFLAGS="-C target-feature=+aes,+sha2,+neon"
```

before building. Decrypt throughput on a 1M-entry fixture is roughly **5×** faster with the flags set than without. There is no equivalent for WebAssembly; `spass-wasm` runs pure-software AES + SHA-2.

## Security

- Sensitive types (`EntryPassword`, `DerivedKey`) zeroize on drop
- Constant-time 100 µs sleep on decryption failure prevents timing oracles
- Passwords are never logged or included in error messages
- CBC mode has no authentication tag -- a property of the `.spass` format itself, not a design choice here

See [SECURITY.md](SECURITY.md) for the full policy and how to report vulnerabilities.

## Development

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
cargo doc --workspace --no-deps --open
```

### Pre-push gate

Before pushing, run the consolidated check:

```bash
bash scripts/ci-check.sh
```

It runs fmt + clippy + tests + doctests + doc + audit in parallel and treats warnings as errors. It is the local mirror of GitHub Actions CI -- if it fails locally, CI will fail too. The script auto-applies `cargo fmt` fixes; a green run that includes "applied formatting fixes" still requires staging + committing those changes before push.

`SPASS_CI_SKIP_IGNORED=1` skips `#[ignore]`-gated tests (e.g. `generate_1m_fixture`) on hosts that can't satisfy them. Default behaviour: include them on Darwin, skip on Linux CI.

## License

Dual-licensed under either of:

- MIT license ([LICENSE-MIT](LICENSE-MIT))
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

at your option.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).
