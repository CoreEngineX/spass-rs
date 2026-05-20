//! Output formatting for password entries.

use colored::Colorize;
use spass::domain::PasswordEntryCollection;
use spass::export::{CsvExporter, JsonExporter};
use std::io::Write;

use crate::cli::OutputFormat;
use crate::error::{CliError, CliResult};

/// Formats and writes password entries to output.
pub struct OutputFormatter;

impl OutputFormatter {
    /// Writes the password collection to the given writer in the specified format.
    pub fn write<W: Write>(
        writer: &mut W,
        collection: &PasswordEntryCollection,
        format: OutputFormat,
    ) -> CliResult<()> {
        match format {
            OutputFormat::Csv => CsvExporter::write(writer, collection)
                .map_err(|e| CliError::OutputWrite(e.to_string())),
            OutputFormat::Json => JsonExporter::write(writer, collection)
                .map_err(|e| CliError::OutputWrite(e.to_string())),
        }
    }

    /// Displays a summary of decrypted entries to stdout.
    pub fn display_summary(collection: &PasswordEntryCollection) {
        let count = collection.len();
        let with_url = collection
            .iter()
            .filter(|e| !e.url.as_str().is_empty())
            .count();

        println!();
        println!(
            "{} {}",
            "ok".green().bold(),
            "Decryption successful!".bold()
        );
        println!();
        println!("  {} {}", "Decrypted:".bold(), count.to_string().cyan());
        if with_url > 0 {
            println!(
                "  {} {} with URLs",
                "Websites:".bold(),
                with_url.to_string().cyan()
            );
        }
        println!();
    }
}
