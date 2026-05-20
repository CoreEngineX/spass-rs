//! High-level decryption pipeline.
//!
//! This module provides the main entry point for decrypting `SPass` files,
//! orchestrating the entire process from file reading to parsed password entries.

mod builder;
mod decrypt;

pub use builder::PipelineBuilder;
pub use decrypt::DecryptionPipeline;
