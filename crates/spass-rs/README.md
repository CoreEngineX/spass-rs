# spass

Core library for decrypting Samsung Pass (`.spass`) export files and converting them to portable formats.

Supports Samsung Pass V3.0, V3.1 and V3.2. A decrypt returns every kept field in one buffer that is zeroed when it is dropped. Files using an unrecognised future version route to a schema-driven decoder that extracts what it can and surfaces a structured diagnostic for a "help us add support" loop.

Full docs and design rationale: [github.com/CoreEngineX/spass-rs](https://github.com/CoreEngineX/spass-rs).

## Usage

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

for entry in &outcome.entries {
    println!("{}: {}", entry.name, entry.username);
}

if let VersionStatus::BestEffort { report } = outcome.version_status {
    eprintln!(
        "warning: unknown .spass version \"{}\"; verify entries before importing",
        report.sentinel,
    );
    eprintln!("help us add support: {}", report.github_issue_url(ReportSource::Cli));
}
```

`DecryptionPipeline::default()` uses 70,000 PBKDF2 iterations (the value Samsung Pass actually uses). The pipeline returns a `DecryptOutcome` carrying an `EntryBuffer`, whose entries are borrowed views into it, plus a `VersionStatus`. For a recognised version you get `Known { version }`; for an unrecognised one you get `BestEffort { report }` with `subject` / `body` / `github_issue_url` / `mailto_url` helpers for the contribution flow. `CsvExporter` and `JsonExporter` write an `EntryBuffer` to any `Write`.

## License

Licensed under either of MIT or Apache-2.0 at your option.
