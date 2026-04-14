use crate::domain::{DecryptedData, SpassError, SpassResult};
use std::io::{BufRead, BufReader, Cursor};

/// Validates the structure and content of decrypted `.spass` data.
#[derive(Default)]
pub struct FormatValidator;

impl FormatValidator {
    /// Constructs a `FormatValidator`.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Checks that line 3 of the decrypted data is exactly `next_table`.
    ///
    /// Samsung Pass uses `next_table` as a section separator in its internal
    /// CSV format. Its presence on line 3 is a reliable indicator that decryption
    /// succeeded and the file is a genuine export.
    ///
    /// # Errors
    ///
    /// Returns `SpassError::Validation` if the data has fewer than 3 lines,
    /// a line cannot be read, or line 3 is not `next_table`.
    pub fn validate_spass_marker(&self, data: &DecryptedData) -> SpassResult<()> {
        let cursor = Cursor::new(data.as_bytes());
        let reader = BufReader::new(cursor);

        for (line_num, line_result) in reader.lines().enumerate() {
            if line_num == 2 {
                let line_content = line_result
                    .map_err(|e| SpassError::Validation(format!("Failed to read line: {e}")))?;

                if line_content.trim() == "next_table" {
                    return Ok(());
                }
                return Err(SpassError::Validation(format!(
                    "Expected 'next_table' on line 3, found '{}'",
                    line_content.trim()
                )));
            }
        }

        Err(SpassError::Validation(
            "Insufficient data lines to validate marker".to_string(),
        ))
    }

    /// Checks that the decrypted data is non-empty and does not exceed 100 MB.
    ///
    /// # Errors
    ///
    /// Returns `SpassError::Validation` if the data is empty or exceeds 100 MB.
    pub fn validate_data_size(&self, data: &DecryptedData) -> SpassResult<()> {
        const MAX_DATA_SIZE: usize = 100 * 1024 * 1024;

        if data.is_empty() {
            return Err(SpassError::Validation("Data cannot be empty".to_string()));
        }

        if data.len() > MAX_DATA_SIZE {
            return Err(SpassError::Validation(
                "Data size exceeds maximum allowed size".to_string(),
            ));
        }

        Ok(())
    }
}
