//! Decrypt command implementation.

use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use spass::domain::EntryPassword;
use spass::pipeline::DecryptionPipeline;
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
        // Get password (from arg or prompt)
        let password = self.get_password()?;

        // Show starting message
        println!(
            "{} Decrypting {}...",
            "→".cyan().bold(),
            self.input.display().to_string().bold()
        );

        // Create progress bar if enabled
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

        // Step 1: Create pipeline
        if let Some(ref pb) = progress {
            pb.set_message("Initializing decryption pipeline...");
        }

        let pipeline = DecryptionPipeline::new(self.iterations);

        // Step 2: Decrypt file
        if let Some(ref pb) = progress {
            pb.set_message(format!(
                "Deriving key with {} iterations...",
                self.iterations
            ));
        }

        let collection = pipeline.decrypt_file(&self.input, &password).map_err(|e| {
            if let Some(ref pb) = progress {
                pb.finish_and_clear();
            }
            CliError::from(e)
        })?;

        // Finish progress bar
        if let Some(ref pb) = progress {
            pb.finish_and_clear();
        }

        // Step 3: Write output
        self.write_output(&collection)?;

        // Step 4: Display summary
        OutputFormatter::display_summary(&collection);

        Ok(())
    }

    /// Gets the password from arguments or prompts the user.
    fn get_password(&self) -> CliResult<EntryPassword> {
        let password_str = if let Some(ref pwd) = self.password {
            pwd.clone()
        } else {
            // Prompt for password
            println!("{}", "Enter decryption password:".bold());
            rpassword::read_password().map_err(|e| CliError::PasswordInput(e.to_string()))?
        };

        if password_str.is_empty() {
            return Err(CliError::Validation("Password cannot be empty".to_string()));
        }

        Ok(EntryPassword::new(password_str))
    }

    /// Writes the output to file or stdout.
    fn write_output(&self, collection: &spass::domain::PasswordEntryCollection) -> CliResult<()> {
        if let Some(ref output_path) = self.output {
            // Write to file
            let file = File::create(output_path).map_err(|e| {
                CliError::OutputWrite(format!("Failed to create output file: {}", e))
            })?;

            let mut writer = BufWriter::new(file);
            OutputFormatter::write(&mut writer, collection, self.format)?;

            println!(
                "  {} {}",
                "Output:".bold(),
                output_path.display().to_string().cyan()
            );
        } else {
            // Write to stdout
            let stdout = io::stdout();
            let mut writer = stdout.lock();
            OutputFormatter::write(&mut writer, collection, self.format)?;
        }

        Ok(())
    }
}
