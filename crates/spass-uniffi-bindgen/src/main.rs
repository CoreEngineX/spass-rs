//! `UniFFI` bindgen entry point, in its own package so `uniffi`'s `cli` feature stays out of the
//! shipped library's dependencies.
//!
//! Invoked by `spass-ios/scripts/build-ios.sh` and `spass-android/scripts/build-android.sh`:
//!
//! ```bash
//! cargo run -p spass-uniffi-bindgen --bin uniffi-bindgen -- \
//!     generate \
//!     --library target/aarch64-apple-ios/release/libspass_uniffi.a \
//!     --language swift \
//!     --out-dir <generated-output-dir>
//! ```

fn main() {
    uniffi::uniffi_bindgen_main();
}
