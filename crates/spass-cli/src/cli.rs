//! CLI argument definitions using Clap.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Samsung Pass Decryptor - Decrypt and convert .spass files
#[derive(Parser, Debug)]
#[command(name = "spass")]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Decrypt a .spass file and export to various formats
    Decrypt {
        /// Path to the .spass file to decrypt
        #[arg(value_name = "FILE")]
        input: PathBuf,

        /// Output file path (defaults to stdout or <input>.csv)
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,

        /// Password for decryption (will prompt if not provided)
        #[arg(short, long, value_name = "PASSWORD")]
        password: Option<String>,

        /// Output format
        #[arg(short, long, value_name = "FORMAT", default_value = "csv")]
        format: OutputFormat,

        /// Number of PBKDF2 iterations
        #[arg(long, value_name = "N", default_value_t = spass::crypto::PBKDF2_ITERATIONS)]
        iterations: u32,

        /// Don't show progress bar
        #[arg(long)]
        no_progress: bool,
    },

    /// Show information about a .spass file without decrypting
    Info {
        /// Path to the .spass file
        #[arg(value_name = "FILE")]
        input: PathBuf,
    },

    /// Generate a synthetic .spass fixture file with N password entries
    Generate {
        /// Number of password entries to generate
        #[arg(value_name = "N")]
        count: usize,

        /// Output path for the generated .spass file
        #[arg(short, long, value_name = "FILE", default_value = "generated.spass")]
        output: PathBuf,

        /// Encryption password for the generated file
        #[arg(
            short,
            long,
            value_name = "PASSWORD",
            default_value = "TestPassword123"
        )]
        password: String,

        /// Fraction of entries with a missing URL (0.0–1.0)
        #[arg(long, value_name = "FRAC", default_value_t = 0.005)]
        warning_rate: f64,

        /// Fraction of entries that are duplicates (0.0–1.0)
        #[arg(long, value_name = "FRAC", default_value_t = 0.02)]
        duplicate_rate: f64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Csv,
    Json,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "csv" => Ok(OutputFormat::Csv),
            "json" => Ok(OutputFormat::Json),
            _ => Err(format!("Invalid format: {}. Valid formats: csv, json", s)),
        }
    }
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputFormat::Csv => write!(f, "csv"),
            OutputFormat::Json => write!(f, "json"),
        }
    }
}
