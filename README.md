# spass-core

A secure, type-safe Rust library and toolchain for decrypting Samsung Pass (`.spass`) export files and converting them to CSV or JSON.

## Problem

Samsung Pass only exports passwords as encrypted `.spass` files that restore on other Samsung devices. That makes it impossible to migrate to Apple Passwords, Chrome, Bitwarden, or any other manager.

`spass-core` decrypts those files and converts them to portable formats every password manager can import. It ships as a library, a CLI, and FFI-friendly bindings for native and web apps.

## Features

- AES-256-CBC decryption with PBKDF2-HMAC-SHA256 (70,000 iterations)
- Strict support for both known Samsung Pass plaintext formats: **V3.0** (`spass_export_v1` line-1 sentinel) and **V3.1** (`31` sentinel)
- **Best-effort parsing for future / unknown versions** -- files with an unrecognised line-1 sentinel route to a schema-driven lenient parser that resolves the 5 required columns by name and extracts what it can, with a structured diagnostic for the contribution loop. See [Unknown / future versions](#unknown--future-versions) below.
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
use spass::domain::{EntryPassword, VersionStatus};

let pipeline = DecryptionPipeline::default();
let password = EntryPassword::new("my_password".to_string());

let outcome = pipeline.decrypt_file("passwords.spass", &password)?;

for entry in outcome.entries.iter() {
    println!("{}: {}", entry.name.as_str(), entry.username.as_str());
}

// Inspect whether the file went through a strict known-version parser
// or the schema-driven lenient fallback. The lenient path means the
// file's sentinel was unrecognised; the report carries everything a
// consumer needs to render a "help us add support" prompt.
match outcome.version_status {
    VersionStatus::Known { version } => {
        println!("decrypted as {:?}", version);
    }
    VersionStatus::BestEffort { report } => {
        eprintln!(
            "warning: unknown version {:?}; verify entries before importing",
            report.sentinel,
        );
        eprintln!("  help us add support: {}", report.github_issue_url());
    }
    _ => {}
}
```

`DecryptionPipeline::default()` uses the canonical `PBKDF2_ITERATIONS` constant (70 000). Pass `DecryptionPipeline::new(N)` to test with a lower iteration count in benchmarks.

`pipeline.decrypt_file` and `decrypt_string` return a `DecryptOutcome` carrying both the extracted entries and a `VersionStatus`. The `Known` arm fires on the two strict-supported formats; `BestEffort { report }` fires when the lenient parser handled an unrecognised version.

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

The bindings return an `FfiDecryptOutcome` record carrying:

- `entries_json: String` -- the decrypted entries as a JSON-encoded array. One Swift string allocation instead of N struct marshals; decode on the Swift side with `JSONDecoder` against a matching Swift struct.
- `version_status: FfiVersionStatus` -- a discriminated union with cases `.known(version)` and `.bestEffort(report)`. The report mirrors the Rust-side `BestEffortReport` and exposes the same pre-built `subject` / `body` / `githubIssueUrl` / `mailtoUrl` fields so the Swift layer can present a Mail-composer / Safari-view contribution prompt without reimplementing anything.

The failure-path `SpassError::UnknownVersionUnparseable` surfaces as `SpassFfiError.UnknownVersion(report)` so the Swift catch arm can route directly to an "unsupported version" screen.

## Web bindings (WebAssembly)

`spass-wasm` is a [wasm-bindgen](https://rustwasm.github.io/wasm-bindgen/) wrapper. Build with `wasm-pack`:

```bash
wasm-pack build crates/spass-wasm --target web --release
```

That produces a `pkg/` directory with a `.wasm` blob, a TS-typed JS shim, and the type definitions. Import it from any modern bundler (Next.js, Vite, etc.).

The exported `decrypt(file_text, password)` returns a JSON string of shape:

```json
{
  "entries": [{ "url": "...", "username": "...", "password": "...", "name": "...", "note": "..." }],
  "version_status": { "kind": "known", "version": "V30" }
}
```

or with `"kind": "best_effort"` plus a `report` carrying the diagnostic. The failure-path `UnknownVersionUnparseable` is thrown as a JS error whose `message` is a JSON payload with `kind: "unknown_version_unparseable"` and the same `report` shape, so the consumer can catch + render an inline contribution panel without re-parsing.

There is no hardware crypto path in wasm; throughput is lower than native but well within interactive latency for typical file sizes.

## Format support

| Version | Status | Line-1 sentinel (in decrypted plaintext) |
|---|---|---|
| V3.0 | Strict | `spass_export_v1` -- the literal Samsung writes |
| V3.1 | Strict | `31` -- numeric |
| Future / unknown | Best-effort | anything else (e.g. `32`) -- see below |

`SpassFormatVersion::detect()` in `crates/spass-rs/src/format/version.rs` reads the first newline-terminated line of decrypted plaintext and dispatches: known sentinels go to the strict, version-specific parser; unknown sentinels go to the lenient parser.

Adding strict V3.2 support later means a new variant + a new arm in `detect()` + a new `parser/v32/` module; consumers using the non-exhaustive enum will not break.

Note: historical versions of the in-tree testkit wrote the literal `30` for V3.0 fixtures. Real Samsung Pass V3.0 files write `spass_export_v1`. The library accepts the latter (matches real exports) and routes the former through the lenient parser as an unknown sentinel. If you have an old test fixture, regenerate it from the current testkit for the strict path.

## Unknown / future versions

When Samsung ships a format we don't strictly support yet, files route to the schema-driven lenient parser at `crates/spass-rs/src/parser/lenient.rs`. It:

1. Reads the v31-shape header after the `next_table` marker.
2. Walks the header looking for the 5 canonical column names we project to `PasswordEntry` (`origin_url`, `username_value`, `password_value`, `title`, `credential_memo`).
3. If all 5 are present, tokenizes each row by looked-up index (not hardcoded position, so reordered or appended columns still parse).
4. Returns the entries plus a `BestEffortReport` for the contribution loop.
5. If any required column is absent, returns `SpassError::UnknownVersionUnparseable(Box<BestEffortReport>)` carrying the same diagnostic so the consumer can still build a contribution URL.

The `BestEffortReport` carries header column-name metadata only -- **never row data**. It exposes pre-built `subject()` / `body()` / `github_issue_url()` / `mailto_url()` helpers so consumers don't reimplement the contribution-message format:

```rust
use spass::domain::VersionStatus;

if let VersionStatus::BestEffort { report } = outcome.version_status {
    let url = report.github_issue_url(); // ready-to-open URL
    let body = report.body();             // mail-composer body
}
```

This means support for the next Samsung Pass version can ship within a day or two of a real file landing in an issue, rather than after a full reverse-engineering pass. The shipped CLI / WASM / UniFFI consumers all surface the report through their respective UI affordances (stderr block, JSON `version_status` field, Swift `FfiBestEffortReport`).

See [`spass-docs/rfc/012-best-effort-fallback.md`](https://github.com/CoreEngineX/spass-docs/blob/dev/rfc/012-best-effort-fallback.md) for the full design.

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
