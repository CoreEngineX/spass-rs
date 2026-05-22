//! Decrypt command implementation.

use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use spass::domain::{BestEffortReport, EntryPassword, VersionStatus};
use spass::pipeline::DecryptionPipeline;
use spass::SpassError;
use std::fs::File;
use std::io::{self, BufWriter};
use std::path::PathBuf;

use crate::cli::OutputFormat;
use crate::error::{CliError, CliResult};
use crate::output::OutputFormatter;

/// Executes the decrypt command.
pub struct DecryptCommand {
    pub input: PathBuf,
    pub output: Option<PathBuf>,
    pub password: Option<String>,
    pub format: OutputFormat,
    pub iterations: u32,
    pub no_progress: bool,
}

impl DecryptCommand {
    /// Executes the decrypt command.
    pub fn execute(self) -> CliResult<()> {
        let password = self.get_password()?;

        println!(
            "{} Decrypting {}...",
            "→".cyan().bold(),
            self.input.display().to_string().bold()
        );

        let progress = if !self.no_progress {
            let pb = ProgressBar::new_spinner();
            pb.set_style(
                ProgressStyle::default_spinner()
                    .template("{spinner:.cyan} {msg}")
                    .unwrap(),
            );
            Some(pb)
        } else {
            None
        };

        if let Some(ref pb) = progress {
            pb.set_message("Initializing decryption pipeline...");
        }

        let pipeline = DecryptionPipeline::new(self.iterations);

        if let Some(ref pb) = progress {
            pb.set_message(format!(
                "Deriving key with {} iterations...",
                self.iterations
            ));
        }

        let outcome = match pipeline.decrypt_file(&self.input, &password) {
            Ok(o) => {
                if let Some(ref pb) = progress {
                    pb.finish_and_clear();
                }
                o
            }
            Err(e) => {
                if let Some(ref pb) = progress {
                    pb.finish_and_clear();
                }
                // Surface the contribution prompt on the unparseable-unknown
                // path before the error propagates -- the user just got a
                // failure, but the report lets us recover next release.
                if let SpassError::UnknownVersionUnparseable(ref report) = e {
                    print_best_effort_block(report, /* succeeded */ false);
                }
                return Err(CliError::from(e));
            }
        };

        self.write_output(&outcome.entries)?;
        OutputFormatter::display_summary(&outcome.entries);

        // Print the contribution block AFTER the summary so the success
        // output is the first thing the user sees on a partial-success run.
        if let VersionStatus::BestEffort { ref report } = outcome.version_status {
            print_best_effort_block(report, /* succeeded */ true);
        }

        Ok(())
    }

    fn get_password(&self) -> CliResult<EntryPassword> {
        let password_str = if let Some(ref pwd) = self.password {
            pwd.clone()
        } else {
            println!("{}", "Enter decryption password:".bold());
            rpassword::read_password().map_err(|e| CliError::PasswordInput(e.to_string()))?
        };

        if password_str.is_empty() {
            return Err(CliError::Validation("Password cannot be empty".to_string()));
        }

        Ok(EntryPassword::new(password_str))
    }

    fn write_output(&self, collection: &spass::domain::PasswordEntryCollection) -> CliResult<()> {
        if let Some(ref output_path) = self.output {
            let file = File::create(output_path)
                .map_err(|e| CliError::OutputWrite(format!("Failed to create output file: {e}")))?;

            let mut writer = BufWriter::new(file);
            OutputFormatter::write(&mut writer, collection, self.format)?;

            println!(
                "  {} {}",
                "Output:".bold(),
                output_path.display().to_string().cyan()
            );
        } else {
            let stdout = io::stdout();
            let mut writer = stdout.lock();
            OutputFormatter::write(&mut writer, collection, self.format)?;
        }

        Ok(())
    }
}

/// Prints the best-effort contribution block to stderr. `succeeded` switches
/// between the "we extracted on best-effort" copy and the "we couldn't parse"
/// copy. The body is intentionally human-readable; the GitHub issue URL is
/// the load-bearing part -- one click sends the diagnostic.
fn print_best_effort_block(report: &BestEffortReport, succeeded: bool) {
    eprintln!();
    if succeeded {
        eprintln!(
            "{} this file uses unknown .spass version \"{}\"",
            "warning:".yellow().bold(),
            report.sentinel
        );
        eprintln!(
            "  extracted {} entries on a best-effort basis",
            report.entries_extracted
        );
        eprintln!("  verify a few entries before importing");
    } else {
        eprintln!(
            "{} this file uses unknown .spass version \"{}\" and could not be parsed",
            "note:".cyan().bold(),
            report.sentinel
        );
        if !report.missing_required_columns.is_empty() {
            eprintln!(
                "  missing required column(s): {}",
                report.missing_required_columns.join(", ")
            );
        }
    }
    eprintln!("  help add support for this version:");
    eprintln!("    {}", report.github_issue_url());
    eprintln!();
}
