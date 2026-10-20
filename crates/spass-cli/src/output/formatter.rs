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

/// `bytes / unit` rounded to `places` decimal places, in integer arithmetic.
pub fn scaled(bytes: u64, unit: u64, places: u32) -> String {
    let factor = 10u128.pow(places);
    let unit = u128::from(unit);
    let value = (u128::from(bytes) * factor + unit / 2) / unit;
    if places == 0 {
        return value.to_string();
    }
    let width = usize::try_from(places).unwrap_or(usize::MAX);
    format!("{}.{:0width$}", value / factor, value % factor)
}

#[cfg(test)]
mod tests {
    use super::scaled;

    #[test]
    fn scaled_rounds_to_the_requested_places() {
        assert_eq!(scaled(1536, 1024, 2), "1.50");
        assert_eq!(scaled(0, 1024, 2), "0.00");
        assert_eq!(scaled(1023, 1024, 2), "1.00");
        assert_eq!(scaled(103_611_740, 1_048_576, 1), "98.8");
        assert_eq!(scaled(5, 1, 0), "5");
    }
}
