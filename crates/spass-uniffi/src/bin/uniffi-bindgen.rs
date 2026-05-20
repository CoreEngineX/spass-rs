//! UniFFI bindgen entry point.
//!
//! Invoked by `scripts/build-ios.sh` to emit Swift bindings:
//!
//! ```bash
//! cargo run --release --bin uniffi-bindgen -- \
//!     generate \
//!     --library target/aarch64-apple-ios/release/libspass_uniffi.a \
//!     --language swift \
//!     --out-dir <generated-output-dir>
//! ```

fn main() {
    uniffi::uniffi_bindgen_main();
}
