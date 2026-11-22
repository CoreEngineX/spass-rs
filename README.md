# spass-core

A secure, type-safe Rust library and toolchain for decrypting Samsung Pass (`.spass`) export files and converting them to CSV or JSON.

## Problem

Samsung Pass only exports passwords as encrypted `.spass` files that restore on other Samsung devices. That makes it impossible to migrate to Apple Passwords, Chrome, Bitwarden, or any other manager.

`spass-core` decrypts those files and converts them to portable formats every password manager can import. It ships as a library, a CLI, and FFI-friendly bindings for native and web apps.

## Features

- AES-256-CBC decryption with PBKDF2-HMAC-SHA256 (70,000 iterations)
- Strict support for both known Samsung Pass plaintext formats: **V3.0** (`spass_export_v1` line-1 sentinel) and **V3.1** (`31` sentinel)
- **One default parser for the 35-column family, best-effort for unknown versions** -- v31, v32, and any unrecognised line-1 sentinel all go through a schema-driven parser that resolves the 5 required columns by name; unknown sentinels additionally surface a structured diagnostic for the contribution loop. See [Unknown / future versions](#unknown--future-versions) below.
- CSV and JSON export
- Interactive CLI with password prompting, progress bars, and coloured output
- File inspection -- view `.spass` structure without decrypting
- The password, the derived key, the decrypted bytes and the cipher state zeroized on drop (see Security)
- Constant-time error handling to prevent timing side-channels
- Hardware AES and SHA-256 detected at runtime on ARMv8 and x86, with no build flags (see Hardware crypto below)
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
spass = "0.3"
```

```rust
use spass::pipeline::DecryptionPipeline;
use spass::domain::{EntryPassword, ReportSource, VersionStatus};

let pipeline = DecryptionPipeline::default();
let password = EntryPassword::new("my_password".to_string());

let outcome = pipeline.decrypt_file("passwords.spass", &password)?;

// Each `EntryRef` borrows its fields from the one buffer; nothing is copied.
for entry in &outcome.entries {
    println!("{}: {}", entry.name, entry.username);
}

// Inspect whether the file's version sentinel was recognised.
// The best-effort path means the
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
        eprintln!(
            "  help us add support: {}",
            report.github_issue_url(ReportSource::Cli)
        );
    }
    _ => {}
}
```

`DecryptionPipeline::default()` uses the canonical `PBKDF2_ITERATIONS` constant (70 000). Pass `DecryptionPipeline::new(NonZeroU32::new(N).unwrap())` to test with a lower iteration count in benchmarks.

`pipeline.decrypt_file(path, &password)` and `pipeline.decrypt_to_buffer(&bytes, &password)` return a `DecryptOutcome` carrying the entries and a `VersionStatus`. The entries are one `EntryBuffer`: every kept field in a single allocation, read through `len()`, `get(i)` and `iter()` as borrowed `EntryRef<'_>` views, and zeroed when it is dropped. It is not `Clone`, so the plaintext has one owner. `CsvExporter::write` and `JsonExporter::write` take the buffer directly. The `Known` arm fires on the recognised sentinels (v30, v31, v32); `BestEffort { report }` fires on an unrecognised version.

`decrypt_to_buffer` takes the file's bytes, not text: one leading UTF-8 byte order mark is skipped, and a file whose decoded size could pass the 100 MiB plaintext cap is refused before the Base64 step and before PBKDF2.

The collection API of earlier releases (`PasswordEntry`, `PasswordEntryCollection`, the `parser` module and `decrypt_string`) is gone; this is a breaking release.

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

`spass-uniffi` is the Swift and Kotlin boundary. The decrypted entries do not go through [UniFFI](https://github.com/mozilla/uniffi-rs): they cross as one buffer through two hand-written C functions declared in `crates/spass-uniffi/include/spass_entries.h`, and UniFFI carries only the version status, the errors and the ABI version check.

Quick build (single iOS arch, simulator):

```bash
cargo build -p spass-uniffi --release \
  --target aarch64-apple-ios-sim
```

For a shipping app, `spass-ios/scripts/build-ios.sh` builds the device and simulator slices, generates the Swift bindings, adds `spass_entries.h` to the xcframework's module map, and assembles `SpassFFI.xcframework` (link it, never embed it). Do not set crypto target-feature flags (see Hardware crypto below).

- `spass_decrypt_entries(file, file_len, password, password_len, &out, &status)` decrypts and hands the buffer over in one call. Code 0: `out` holds the buffer and `status` a lowered `FfiVersionStatus`, a union with cases `.known(version)` and `.bestEffort(report)`. Code 1: `status` holds a lowered `SpassFfiError`. Code 2: the core panicked and nothing was written. The caller lifts `status` with the generated converters.
- `spass_entries_free(out)` zeroes and frees the buffer. Call it exactly once, with the struct `spass_decrypt_entries` wrote. The iOS app owns it through a `~Copyable` struct whose `deinit` calls it; the Android app through a file-private `AutoCloseable` used once.
- `entries_abi_version()` is the one UniFFI function. Each app compares it with `SPASS_ENTRIES_ABI_VERSION` from the header at startup, which also runs UniFFI's own checksum checks.

The buffer layout (every kept field in slot order, then five little-endian `u32` end offsets per entry) is in `spass-docs/spass-core-api.md`, section 5.4. The report in a `bestEffort` status exposes pre-built `subject` / `body` / `githubIssueUrl` / `mailtoUrl` fields so an app can present a contribution prompt without reimplementing anything.

The failure-path `SpassError::UnknownVersionUnparseable` surfaces as `SpassFfiError.UnknownVersion(report)` so the Swift catch arm can route directly to an "unsupported version" screen.

## Web bindings (WebAssembly)

`spass-wasm` is a [wasm-bindgen](https://rustwasm.github.io/wasm-bindgen/) wrapper. Build with `wasm-pack`:

```bash
wasm-pack build crates/spass-wasm --target web --release
```

That produces a `pkg/` directory with a `.wasm` blob, a TS-typed JS shim, and the type definitions. Import it from any modern bundler (Next.js, Vite, etc.).

The exported `decrypt_entries(file, password)` takes the file's bytes and returns a `DecryptedEntries` object that owns the buffer inside WebAssembly memory: `count()`, `bytes_ptr()`, `bytes_len()`, `index_offset()` and `version_status()`, a JSON string such as `{"kind":"known","version":"V30"}` or `{"kind":"best_effort","report":{...}}`. Read `version_status()` and the four numbers first, then make the views over `memory.buffer` and decode every field, then call `free()`, which zeroes the buffer. Any call into the module can grow its memory and detach a view, so nothing is called while a view is alive (`spass-web/lib/spass.ts` is the reference reader).

A failure rejects with the error's message, or for `UnknownVersionUnparseable` with a JSON payload of `kind: "unknown_version_unparseable"` and the same `report` shape, so the consumer can catch and render an inline contribution panel without re-parsing.

There is no hardware crypto path in wasm; throughput is lower than native but well within interactive latency for typical file sizes.

## Format support

| Version          | Status                                              | Line-1 sentinel (in decrypted plaintext)        |
| ---------------- | --------------------------------------------------- | ----------------------------------------------- |
| V3.0             | Known -- dedicated parser                           | `spass_export_v1` -- the literal Samsung writes |
| V3.1             | Known -- default schema parser                      | `31` -- numeric                                 |
| V3.2             | Known -- default schema parser (same layout as v31) | `32` -- numeric                                 |
| Future / unknown | Best-effort -- same schema parser                   | anything else (e.g. `33`) -- see below          |

`SpassFormatVersion::detect()` in `crates/spass-rs/src/format/version.rs` reads the first newline-terminated line of decrypted plaintext and dispatches by wire family: v30 has its own decoder (`crates/spass-rs/src/entries/decode/v30.rs`); every 35-column version -- known or unknown -- goes through the one schema decoder at `crates/spass-rs/src/entries/decode/schema.rs`.

Adding a future same-layout version means one new enum variant, one `detect()` arm, and one `wire_family()` line -- no parser code; consumers using the non-exhaustive enum will not break.

Note: historical versions of the in-tree testkit wrote the literal `30` for V3.0 fixtures. Real Samsung Pass V3.0 files write `spass_export_v1`. The library accepts the latter (matches real exports) and routes the former through the schema parser as an unknown sentinel. If you have an old test fixture, regenerate it from the current testkit.

## Unknown / future versions

When Samsung ships a format we don't know yet, files route to the same schema decoder that serves v31/v32 (`crates/spass-rs/src/entries/decode/schema.rs`) -- just tagged `BestEffort` instead of `Known`. The decoder:

1. Reads the 35-column-shape header after the `next_table` marker.
2. Walks the header looking for the 5 canonical column names it keeps (`origin_url`, `username_value`, `password_value`, `title`, `credential_memo`).
3. If all 5 are present, reads each row's cells by looked-up index (not hardcoded position, so reordered or appended columns still parse) and writes the five kept fields into the `EntryBuffer`.
4. Returns the buffer plus a `BestEffortReport` for the contribution loop.
5. If any required column is absent, returns `SpassError::UnknownVersionUnparseable(Box<BestEffortReport>)` carrying the same diagnostic so the consumer can still build a contribution URL.

The `BestEffortReport` carries header column-name metadata only -- **never row data**. It exposes pre-built `subject()` / `body(source)` / `github_issue_url(source)` / `mailto_url(to, source)` helpers so consumers don't reimplement the contribution-message format. The `ReportSource` argument (`IosApp` / `AndroidApp` / `WebApp` / `Cli`) stamps a closing "Sent from ..." line naming the platform; the subject and the rest of the body stay identical across platforms:

```rust
use spass::domain::{ReportSource, VersionStatus};

if let VersionStatus::BestEffort { report } = outcome.version_status {
    let url = report.github_issue_url(ReportSource::Cli); // ready-to-open URL
    let body = report.body(ReportSource::Cli);            // mail-composer body
}
```

This means support for the next Samsung Pass version can ship within a day or two of a real file landing in an issue, rather than after a full reverse-engineering pass. The shipped CLI / WASM / UniFFI consumers all surface the report through their respective UI affordances (stderr block, JSON `version_status` field, Swift `FfiBestEffortReport`).

See [`spass-docs/rfc/012-best-effort-fallback.md`](https://github.com/CoreEngineX/spass-docs/blob/dev/rfc/012-best-effort-fallback.md) for the original best-effort design and [`spass-docs/rfc/014-spass-format-v32.md`](https://github.com/CoreEngineX/spass-docs/blob/dev/rfc/014-spass-format-v32.md) for the consolidation into one default parser.

## Hardware crypto

`spass-core` uses the `aes` and `sha2` crates, which pick their backend at runtime: the ARMv8 AES and SHA-256 instructions on arm64 (iOS, Android, Apple Silicon Macs), and AES-NI and SHA-NI on x86. No target needs `RUSTFLAGS`.

**Do not pass `-C target-feature=+aes,+sha2`.** With those flags the crates assume the instructions instead of detecting them. ARM's crypto extension is optional, so an Android build made that way crashes on a CPU without it.

To confirm a built library uses the hardware path, count its AES instructions; symbol names do not show it:

```bash
"$(rustc --print sysroot)/lib/rustlib/aarch64-apple-darwin/bin/llvm-objdump" -d --no-show-raw-insn libspass_uniffi.a | grep -c -w aesd
```

There is no hardware path in WebAssembly; `spass-wasm` runs the constant-time software AES and SHA-256.

## Security

- `EntryPassword`, `DerivedKey` and the `EntryBuffer` zeroize on drop, and so do the AES round keys and the CBC state (the `aes` and `cbc` `zeroize` features). The decrypt runs in place in one zeroizing buffer, and every intermediate that holds plaintext (V30's first buffer, the per-row scratch, the exporters' output chunks) is zeroed when it is freed; no plaintext buffer grows by reallocation, which would free the old block unzeroed. Not wiped: the HMAC and PBKDF2 intermediate state, and whatever a consumer copies the fields into (Swift and Kotlin strings, JavaScript strings)
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
