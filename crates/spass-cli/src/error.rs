//! CLI error types with user-friendly messages.

use colored::Colorize;
use spass::SpassError;

/// CLI-specific errors with user-friendly messages.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("Failed to read input file: {0}")]
    InputFileRead(#[from] std::io::Error),

    #[error("Decryption failed: {0}")]
    Decryption(String),

    #[error("Invalid file format: {0}")]
    InvalidFormat(String),

    #[error("Parsing failed: {0}")]
    Parsing(String),

    #[error("Validation failed: {0}")]
    Validation(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Failed to write output: {0}")]
    OutputWrite(String),

    #[error("Password input failed: {0}")]
    PasswordInput(String),

    #[error("{0}")]
    Other(String),
}

impl From<SpassError> for CliError {
    fn from(err: SpassError) -> Self {
        match err {
            SpassError::Io(e) => CliError::InputFileRead(e),
            SpassError::Decryption(msg) => CliError::Decryption(msg),
            SpassError::Parsing(msg) => CliError::Parsing(msg),
            SpassError::Validation(msg) => CliError::Validation(msg),
            SpassError::Config(msg) => CliError::Config(msg),
            SpassError::Csv(e) => CliError::InvalidFormat(e.to_string()),
            _ => CliError::Other(format!("Unexpected error: {}", err)),
        }
    }
}

impl CliError {
    /// Display the error with colored output and helpful hints.
    pub fn display_with_hints(&self) {
        eprintln!("{} {}", "Error:".red().bold(), self);

        // Provide helpful hints based on error type
        match self {
            CliError::Decryption(_) => {
                eprintln!("\n{}", "Hint:".yellow().bold());
                eprintln!("  • Make sure you're using the correct password");
                eprintln!("  • The password is case-sensitive");
                eprintln!(
                    "  • This should be the password you set when exporting from Samsung Pass"
                );
            }
            CliError::InvalidFormat(_) => {
                eprintln!("\n{}", "Hint:".yellow().bold());
                eprintln!("  • Make sure the file is a valid .spass export");
                eprintln!("  • The file may be corrupted");
                eprintln!("  • Try exporting again from Samsung Pass");
            }
            CliError::InputFileRead(_) => {
                eprintln!("\n{}", "Hint:".yellow().bold());
                eprintln!("  • Check that the file path is correct");
                eprintln!("  • Make sure you have permission to read the file");
            }
            CliError::OutputWrite(_) => {
                eprintln!("\n{}", "Hint:".yellow().bold());
                eprintln!("  • Check that you have write permission for the output directory");
                eprintln!("  • Make sure there's enough disk space");
            }
            _ => {}
        }
    }
}

/// Result type for CLI operations.
pub type CliResult<T> = Result<T, CliError>;
