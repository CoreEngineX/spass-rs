# spass

Core library for decrypting Samsung Pass (`.spass`) export files and converting them to portable formats.

Supports Samsung Pass V3.0 and V3.1 with strict, version-specific parsers. Files using an unrecognised future version route to a schema-driven lenient parser that extracts what it can and surfaces a structured diagnostic for a "help us add support" loop.

Full docs and design rationale: [github.com/CoreEngineX/spass-rs](https://github.com/CoreEngineX/spass-rs).

## Usage

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

if let VersionStatus::BestEffort { report } = outcome.version_status {
    eprintln!(
        "warning: unknown .spass version \"{}\"; verify entries before importing",
        report.sentinel,
    );
    eprintln!("help us add support: {}", report.github_issue_url());
}
```

`DecryptionPipeline::default()` uses 70,000 PBKDF2 iterations (the value Samsung Pass actually uses). The pipeline returns a `DecryptOutcome` carrying the entries plus a `VersionStatus`. On the strict path you get `Known { version }`; on the lenient fallback you get `BestEffort { report }` with pre-built `subject` / `body` / `github_issue_url` / `mailto_url` helpers for the contribution flow.

## License

Licensed under either of MIT or Apache-2.0 at your option.
