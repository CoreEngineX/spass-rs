//! Info command implementation.

use colored::Colorize;
use spass::format::SpassDecoder;
use std::fs;
use std::path::PathBuf;

use crate::error::{CliError, CliResult};

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
        let file_content = fs::read_to_string(&self.input).map_err(CliError::InputFileRead)?;

        let decoder = SpassDecoder::new();
        let decoded = decoder
            .decode_from_string(&file_content)
            .map_err(CliError::from)?;

        // Display information
        println!();
        println!("{}", "File Information".bold().underline());
        println!();
        println!("  {} {}", "Path:".bold(), self.input.display());
        println!(
            "  {} {} bytes ({:.2} KB)",
            "Size:".bold(),
            file_size,
            file_size as f64 / 1024.0
        );
        println!();

        println!("{}", "Structure".bold().underline());
        println!();
        println!("  {} 20 bytes", "Salt length:".bold());
        println!("  {} 16 bytes", "IV length:".bold());
        println!(
            "  {} {} bytes ({:.2} KB)",
            "Ciphertext:".bold(),
            decoded.ciphertext().as_bytes().len(),
            decoded.ciphertext().as_bytes().len() as f64 / 1024.0
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
