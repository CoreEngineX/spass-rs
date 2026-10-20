//! Builder pattern for constructing custom decryption pipelines.

use super::decrypt::DecryptionPipeline;
use crate::crypto::PBKDF2_ITERATIONS;
use std::num::NonZeroU32;

/// Builder for [`DecryptionPipeline`].
///
/// # Examples
///
/// ```
/// use spass::pipeline::PipelineBuilder;
/// use std::num::NonZeroU32;
///
/// const ITERATIONS: NonZeroU32 = NonZeroU32::new(100_000).unwrap();
///
/// let pipeline = PipelineBuilder::new().iterations(ITERATIONS).build();
/// ```
#[derive(Default)]
pub struct PipelineBuilder {
    iterations: Option<NonZeroU32>,
}

impl PipelineBuilder {
    /// Start a builder with no overrides; identical to
    /// [`Self::default`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the PBKDF2 iteration count. Defaults to
    /// [`PBKDF2_ITERATIONS`] (70,000) -- the value Samsung Pass uses
    /// -- if unset. Lowering this only makes sense in tests where
    /// you don't actually need to decrypt a real export.
    #[must_use]
    pub fn iterations(mut self, iterations: NonZeroU32) -> Self {
        self.iterations = Some(iterations);
        self
    }

    /// Construct the configured [`DecryptionPipeline`]. Iteration
    /// count defaults to [`PBKDF2_ITERATIONS`] if `iterations` was
    /// never set.
    #[must_use]
    pub fn build(self) -> DecryptionPipeline {
        let iterations = self.iterations.unwrap_or(PBKDF2_ITERATIONS);
        DecryptionPipeline::new(iterations)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_default() {
        let _ = PipelineBuilder::new().build();
    }

    #[test]
    fn test_builder_with_custom_iterations() {
        let _ = PipelineBuilder::new()
            .iterations(NonZeroU32::new(50_000).unwrap())
            .build();
    }

    #[test]
    fn test_builder_chaining() {
        let _ = PipelineBuilder::new()
            .iterations(NonZeroU32::new(100_000).unwrap())
            .build();
    }
}
