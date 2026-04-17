//! Generate command — builds a synthetic `.spass` fixture with N entries.

use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use spass::testkit::{SpassGenerator, TestEntry};
use std::path::PathBuf;
use std::time::Instant;

use crate::error::CliResult;

const DOMAINS: &[&str] = &[
    "google.com",     "github.com",     "amazon.com",     "netflix.com",
    "spotify.com",    "apple.com",      "microsoft.com",  "dropbox.com",
    "notion.so",      "slack.com",      "figma.com",      "linear.app",
    "vercel.com",     "cloudflare.com", "twitter.com",    "reddit.com",
    "discord.com",    "twitch.tv",      "linkedin.com",   "facebook.com",
    "paypal.com",     "stripe.com",     "shopify.com",    "airbnb.com",
    "uber.com",       "zoom.us",        "atlassian.com",  "salesforce.com",
    "adobe.com",      "canva.com",
];

/// Executes the generate command.
pub struct GenerateCommand {
    pub count: usize,
    pub output: PathBuf,
    pub password: String,
    pub warning_rate: f64,
    pub duplicate_rate: f64,
}

impl GenerateCommand {
    /// Executes the generate command.
    pub fn execute(self) -> CliResult<()> {
        println!(
            "{} Generating {} entries → {}",
            "→".cyan().bold(),
            self.count.to_string().bold(),
            self.output.display().to_string().cyan()
        );

        let pb = ProgressBar::new(self.count as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.cyan} [{bar:40.cyan/white}] {pos}/{len} entries ({eta})")
                .unwrap()
                .progress_chars("█▉▊▋▌▍▎▏  "),
        );

        let build_start = Instant::now();
        let mut gen = SpassGenerator::new(&self.password);

        // Precompute thresholds as integer periods to avoid float comparisons in
        // the hot loop.
        let warn_period = if self.warning_rate > 0.0 {
            (1.0 / self.warning_rate).round() as usize
        } else {
            usize::MAX
        };
        let dup_period = if self.duplicate_rate > 0.0 {
            (1.0 / self.duplicate_rate).round() as usize
        } else {
            usize::MAX
        };

        for i in 0..self.count {
            let domain = DOMAINS[i % DOMAINS.len()];

            let url = if i % warn_period == 0 {
                String::new()
            } else {
                format!("https://{domain}")
            };

            let username = if i % warn_period == 1 {
                String::new()
            } else {
                format!("user{i}@{domain}")
            };

            // Duplicate: reuse url + username from the previous entry.
            let (final_url, final_username) = if i > 0 && i % dup_period == 0 {
                let prev_domain = DOMAINS[(i - 1) % DOMAINS.len()];
                (
                    format!("https://{prev_domain}"),
                    format!("user{}@{prev_domain}", i - 1),
                )
            } else {
                (url, username)
            };

            gen = gen.entry(TestEntry::new(
                final_url,
                final_username,
                format!("P@ss#{i:07}!Sec"),
                format!("Account {i:07}"),
                if i % 5 == 0 { format!("note {i}") } else { String::new() },
            ));

            if i % 5000 == 0 {
                pb.set_position(i as u64);
            }
        }

        pb.finish_and_clear();
        let build_elapsed = build_start.elapsed();
        println!("  {} built in {build_elapsed:.2?}", "Entries".bold());

        println!(
            "  {} encrypting with {} PBKDF2 iterations…",
            "→".cyan(),
            "70 000".bold()
        );
        let enc_start = Instant::now();
        gen.write_to_file(&self.output);
        let enc_elapsed = enc_start.elapsed();

        let size_mb = std::fs::metadata(&self.output)
            .map(|m| m.len() as f64 / 1_048_576.0)
            .unwrap_or(0.0);

        println!("  {} encrypted in {enc_elapsed:.2?}", "Done".green().bold());
        println!();
        println!(
            "  {}  {}",
            "File:".bold(),
            self.output.display().to_string().cyan()
        );
        println!("  {}  {:.1} MB", "Size:".bold(), size_mb);
        println!("  {}  {}", "Password:".bold(), self.password.cyan());

        Ok(())
    }
}
