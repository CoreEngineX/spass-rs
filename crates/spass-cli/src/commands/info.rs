//! Info command implementation.

use colored::Colorize;
use spass::format::SpassDecoder;
use std::fs;
use std::path::PathBuf;

use crate::error::{CliError, CliResult};
use crate::output::formatter::scaled;

/// Executes the info command.
pub struct InfoCommand {
    pub input: PathBuf,
}

impl InfoCommand {
    /// Executes the info command to show file information.
    pub fn execute(self) -> CliResult<()> {
        println!(
            "{} Reading {}...",
            "→".cyan().bold(),
            self.input.display().to_string().bold()
        );

        // Read file metadata
        let metadata = fs::metadata(&self.input).map_err(CliError::InputFileRead)?;

        let file_size = metadata.len();

        // Try to decode the file structure (without decryption)
        let file_bytes = fs::read(&self.input).map_err(CliError::InputFileRead)?;

        let decoded = SpassDecoder::new()
            .decode_from_bytes(&file_bytes)
            .map_err(CliError::from)?;
        let ciphertext_len =
            u64::try_from(decoded.ciphertext().as_bytes().len()).unwrap_or(u64::MAX);

        // Display information
        println!();
        println!("{}", "File Information".bold().underline());
        println!();
        println!("  {} {}", "Path:".bold(), self.input.display());
        println!(
            "  {} {} bytes ({} KB)",
            "Size:".bold(),
            file_size,
            scaled(file_size, 1024, 2)
        );
        println!();

        println!("{}", "Structure".bold().underline());
        println!();
        println!("  {} 20 bytes", "Salt length:".bold());
        println!("  {} 16 bytes", "IV length:".bold());
        println!(
            "  {} {} bytes ({} KB)",
            "Ciphertext:".bold(),
            ciphertext_len,
            scaled(ciphertext_len, 1024, 2)
        );
        println!();

        println!("{}", "Encryption".bold().underline());
        println!();
        println!("  {} AES-256-CBC", "Algorithm:".bold());
        println!("  {} PBKDF2-HMAC-SHA256", "Key Derivation:".bold());
        println!("  {} 70,000 (recommended)", "Iterations:".bold());
        println!();

        println!("{}", "Note:".yellow());
        println!(
            "  To decrypt this file, use: spass decrypt {}",
            self.input.display()
        );
        println!();

        Ok(())
    }
}
