# spass

Core library for decrypting Samsung Pass (`.spass`) export files.

See the [workspace README](../../README.md) for full documentation.

## Usage

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

## License

Licensed under either of MIT or Apache-2.0 at your option.
