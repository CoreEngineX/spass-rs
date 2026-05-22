//! `SPass` file format decoding and validation.

mod decoder;
mod validator;
mod version;

pub use decoder::{CipherText, DecodedFile, InitializationVector, Salt, SpassDecoder};

#[cfg(test)]
pub use decoder::DecodedFileBuilder;
pub use validator::FormatValidator;
pub use version::SpassFormatVersion;

pub(crate) use version::DetectedVersion;
