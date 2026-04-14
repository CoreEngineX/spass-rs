//! Builder pattern for constructing custom decryption pipelines.

use super::decrypt::DecryptionPipeline;
use crate::crypto::PBKDF2_ITERATIONS;

/// Builder for [`DecryptionPipeline`].
///
/// # Examples
///
/// ```
/// use spass::pipeline::PipelineBuilder;
///
/// let pipeline = PipelineBuilder::new()
///     .iterations(100_000)
///     .build();
/// ```
#[derive(Default)]
pub struct PipelineBuilder {
    iterations: Option<u32>,
}

impl PipelineBuilder {
    /// Constructs a `PipelineBuilder` with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the PBKDF2 iteration count.
    ///
    /// Higher values increase resistance to brute-force at the cost of
    /// decryption time. Defaults to 70,000 if not set.
    #[must_use]
    pub fn iterations(mut self, iterations: u32) -> Self {
        self.iterations = Some(iterations);
        self
    }

    /// Builds the configured [`DecryptionPipeline`].
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
        let _ = PipelineBuilder::new().iterations(50_000).build();
    }

    #[test]
    fn test_builder_chaining() {
        let _ = PipelineBuilder::new().iterations(100_000).build();
    }
}
