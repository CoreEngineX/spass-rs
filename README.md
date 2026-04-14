# spass-rs

A secure, type-safe Rust library and CLI for decrypting Samsung Pass (`.spass`) export files and converting them to standard password manager formats.

## Problem

Samsung Pass only exports passwords as encrypted `.spass` files that can only be restored on other Samsung devices. This makes it impossible to migrate to other platforms or password managers.

`spass-rs` solves this by decrypting `.spass` files and converting them to CSV or JSON formats that any password manager can import.

## Features

- AES-256-CBC decryption with PBKDF2-HMAC-SHA256 (70,000 iterations)
- CSV and JSON export
- Interactive CLI with password prompting, progress bars, and colored output
- File inspection — view `.spass` structure without decrypting
- Sensitive data zeroized on drop
- Constant-time error handling to prevent timing side-channels
- CI: fmt, clippy, tests, and cargo-audit on every push

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

## CLI

### Installation

```bash
cargo install --git https://github.com/CoreEngineX/spass-rs spass-cli
```

### Usage

```bash
# Interactive — prompts for password (recommended)
spass decrypt passwords.spass -o output.csv

# Export as JSON
spass decrypt passwords.spass -f json -o output.json

# Write to stdout
spass decrypt passwords.spass > output.csv

# Inspect a file without decrypting
spass info passwords.spass
```

## Project structure

```
crates/
  spass-rs/      # Core library — published to crates.io as `spass`
  spass-cli/     # CLI binary — not published to crates.io
```

## Security

- Sensitive types (`EntryPassword`, `DerivedKey`) zeroize on drop
- Constant-time 100µs sleep on decryption failure prevents timing oracles
- Passwords are never logged or included in error messages
- CBC mode has no authentication tag — constrained by the `.spass` format

See [SECURITY.md](SECURITY.md) for the full policy and how to report vulnerabilities.

## Development

```bash
cargo build
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
cargo doc --open
```

## License

Licensed under either of:

- MIT license ([LICENSE-MIT](LICENSE-MIT))
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

at your option.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).
