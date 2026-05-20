//! Samsung Pass Decryptor CLI
//!
//! A command-line tool to decrypt and convert Samsung Pass `.spass` export files.

mod cli;
mod commands;
mod error;
mod output;

use clap::Parser;

use cli::{Cli, Commands};
use commands::{DecryptCommand, GenerateCommand, InfoCommand};

fn main() {
    // Parse command-line arguments
    let cli = Cli::parse();

    // Execute command
    let result = match cli.command {
        Commands::Decrypt {
            input,
            output,
            password,
            format,
            iterations,
            no_progress,
        } => {
            let cmd = DecryptCommand {
                input,
                output,
                password,
                format,
                iterations,
                no_progress,
            };
            cmd.execute()
        }

        Commands::Info { input } => {
            let cmd = InfoCommand { input };
            cmd.execute()
        }

        Commands::Generate {
            count,
            output,
            password,
            warning_rate,
            duplicate_rate,
        } => {
            let cmd = GenerateCommand {
                count,
                output,
                password,
                warning_rate,
                duplicate_rate,
            };
            cmd.execute()
        }
    };

    // Handle errors
    if let Err(e) = result {
        e.display_with_hints();
        std::process::exit(1);
    }
}
