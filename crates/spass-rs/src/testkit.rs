//! Internal test fixture generator for `.spass` files.
//!
//! Only compiled under `#[cfg(test)]`. Not part of the public API and
//! never included in release builds.
//!
//! # Usage
//!
//! ```rust,ignore
//! use crate::testkit::{SpassGenerator, TestEntry};
//!
//! let data = SpassGenerator::new("my_password")
//!     .entry(TestEntry::new("https://example.com", "user@email.com", "secret123", "Example", ""))
//!     .entry(TestEntry::new("https://github.com", "devuser", "gh_abc123", "GitHub", "Work"))
//!     .generate();
//!
//! // `data` is valid Base64 — write it to a file or pass directly to the pipeline.
//! std::fs::write("test_fixture.spass", &data).unwrap();
//! ```

use aes::Aes256;
use base64::{engine::general_purpose, Engine};
use cbc::cipher::generic_array::GenericArray;
use cbc::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
use cbc::Encryptor;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha256;

/// A single password entry used when generating a test fixture.
#[derive(Debug, Clone)]
pub struct TestEntry {
    /// Entry URL.
    pub url: String,
    /// Entry username.
    pub username: String,
    /// Entry password.
    pub password: String,
    /// Entry display name.
    pub name: String,
    /// Optional note.
    pub note: String,
}

impl TestEntry {
    /// Creates a new test entry from raw string values.
    pub fn new(
        url: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
        name: impl Into<String>,
        note: impl Into<String>,
    ) -> Self {
        Self {
            url: url.into(),
            username: username.into(),
            password: password.into(),
            name: name.into(),
            note: note.into(),
        }
    }

    /// Escapes a CSV field value, wrapping in quotes if it contains a comma,
    /// quote, or newline.
    fn csv_field(value: &str) -> String {
        if value.contains(',') || value.contains('"') || value.contains('\n') {
            format!("\"{}\"", value.replace('"', "\"\""))
        } else {
            value.to_string()
        }
    }

    fn to_csv_row(&self) -> String {
        format!(
            "{},{},{},{},{}",
            Self::csv_field(&self.url),
            Self::csv_field(&self.username),
            Self::csv_field(&self.password),
            Self::csv_field(&self.name),
            Self::csv_field(&self.note),
        )
    }
}

/// Builds a valid `.spass` file from a password and a list of entries.
///
/// The generated file matches the Samsung Pass export format:
///
/// ```text
/// [Samsung internal header — line 1]
/// [Samsung internal header — line 2]
/// next_table
/// URL,Username,Password,Name,Note
/// <entry rows…>
/// ```
///
/// The plaintext is then encrypted with AES-256-CBC (PBKDF2-HMAC-SHA256 key
/// derivation, 70 000 iterations) and Base64-encoded — identical to what
/// Samsung Pass produces.
pub struct SpassGenerator {
    password: String,
    entries: Vec<TestEntry>,
    /// Fixed salt for deterministic fixtures. Defaults to random-looking but
    /// deterministic bytes so the same generator call always produces the same
    /// ciphertext, making snapshot tests stable.
    salt: Option<[u8; 20]>,
    iv: Option<[u8; 16]>,
}

impl SpassGenerator {
    /// Creates a generator that will encrypt with `password`.
    pub fn new(password: impl Into<String>) -> Self {
        Self {
            password: password.into(),
            entries: Vec::new(),
            salt: None,
            iv: None,
        }
    }

    /// Appends an entry.
    #[must_use]
    pub fn entry(mut self, entry: TestEntry) -> Self {
        self.entries.push(entry);
        self
    }

    /// Appends multiple entries.
    #[must_use]
    pub fn entries(mut self, entries: impl IntoIterator<Item = TestEntry>) -> Self {
        self.entries.extend(entries);
        self
    }

    /// Overrides the salt for deterministic output (useful for snapshot tests).
    #[must_use]
    pub fn with_salt(mut self, salt: [u8; 20]) -> Self {
        self.salt = Some(salt);
        self
    }

    /// Overrides the IV for deterministic output (useful for snapshot tests).
    #[must_use]
    pub fn with_iv(mut self, iv: [u8; 16]) -> Self {
        self.iv = Some(iv);
        self
    }

    /// Generates the `.spass` file content as a Base64 string.
    ///
    /// The result can be written directly to a `.spass` file or passed to
    /// `DecryptionPipeline::decrypt_string`.
    #[must_use]
    pub fn generate(&self) -> String {
        let salt = self.salt.unwrap_or([
            0x53, 0x61, 0x6d, 0x73, 0x75, 0x6e, 0x67, 0x54, 0x65, 0x73, 0x74, 0x53, 0x61, 0x6c,
            0x74, 0x56, 0x61, 0x6c, 0x75, 0x65,
        ]);
        let iv = self.iv.unwrap_or([
            0x53, 0x61, 0x6d, 0x73, 0x75, 0x6e, 0x67, 0x49, 0x56, 0x56, 0x61, 0x6c, 0x75, 0x65,
            0x58, 0x58,
        ]);

        let plaintext = self.build_plaintext();
        let ciphertext = Self::encrypt(plaintext.as_bytes(), &self.password, &salt, &iv);

        let mut blob = Vec::with_capacity(20 + 16 + ciphertext.len());
        blob.extend_from_slice(&salt);
        blob.extend_from_slice(&iv);
        blob.extend_from_slice(&ciphertext);

        general_purpose::STANDARD.encode(&blob)
    }

    /// Generates the `.spass` file and writes it to `path`.
    ///
    /// # Panics
    ///
    /// Panics if the file cannot be written.
    pub fn write_to_file(&self, path: impl AsRef<std::path::Path>) {
        let content = self.generate();
        std::fs::write(path, content).expect("Failed to write test fixture");
    }

    // ── private ──────────────────────────────────────────────────────────────

    fn build_plaintext(&self) -> String {
        let mut out = String::new();
        // Lines 1–2: Samsung internal header section (ignored by the parser).
        out.push_str("spass_export_v1\n");
        out.push_str("generated_by_testkit\n");
        // Line 3: section separator — must be exactly `next_table`.
        out.push_str("next_table\n");
        // Lines 4+: password CSV.
        out.push_str("URL,Username,Password,Name,Note\n");
        for entry in &self.entries {
            out.push_str(&entry.to_csv_row());
            out.push('\n');
        }
        out
    }

    fn encrypt_with_iterations(
        plaintext: &[u8],
        password: &str,
        salt: &[u8; 20],
        iv: &[u8; 16],
        iterations: u32,
    ) -> Vec<u8> {
        let mut key = [0u8; 32];
        pbkdf2::<Hmac<Sha256>>(password.as_bytes(), salt, iterations, &mut key)
            .expect("PBKDF2 key derivation failed");

        let key_array = GenericArray::from_slice(&key);
        let iv_array = GenericArray::from_slice(iv);

        // Allocate buffer: plaintext + one full block for padding headroom.
        let mut buffer = plaintext.to_vec();
        buffer.resize(plaintext.len() + 16, 0);

        let encryptor = Encryptor::<Aes256>::new(key_array, iv_array);
        let ciphertext_len = encryptor
            .encrypt_padded_mut::<Pkcs7>(&mut buffer, plaintext.len())
            .expect("AES-CBC encryption failed")
            .len();

        buffer.truncate(ciphertext_len);
        buffer
    }

    fn encrypt(plaintext: &[u8], password: &str, salt: &[u8; 20], iv: &[u8; 16]) -> Vec<u8> {
        Self::encrypt_with_iterations(plaintext, password, salt, iv, 70_000)
    }
}

// ── convenience constructors ──────────────────────────────────────────────────

impl SpassGenerator {
    /// Returns a generator pre-loaded with a realistic set of test entries.
    pub fn with_sample_entries(password: impl Into<String>) -> Self {
        Self::new(password).entries([
            TestEntry::new(
                "https://accounts.google.com",
                "user@gmail.com",
                "G00gleP@ss!",
                "Google",
                "Main",
            ),
            TestEntry::new(
                "https://github.com",
                "devuser",
                "gh_token_abc123",
                "GitHub",
                "Work",
            ),
            TestEntry::new(
                "https://netflix.com",
                "stream@email.com",
                "Netfl1x!",
                "Netflix",
                "",
            ),
            TestEntry::new(
                "android://com.samsung.android.app.samsungpay",
                "user@email.com",
                "SPayP@ss9",
                "Samsung Pay",
                "",
            ),
            TestEntry::new(
                "https://paypal.com",
                "payments@email.com",
                "PayP@l2024!",
                "PayPal",
                "",
            ),
            TestEntry::new("", "admin", "Admin@1234", "Internal Tool", "missing url"),
        ])
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::EntryPassword;
    use crate::pipeline::DecryptionPipeline;

    const TEST_PASSWORD: &str = "test_password_123";
    const FIXTURE_PASSWORD: &str = "TestPassword123";
    const FIXTURE_DIR: &str =
        "/Users/osebhulimenegbor/Developer/CoreEngineX/products/spass-converter/tmp";

    /// Generates 4 `.spass` fixture files into `tmp/` for manual website testing.
    ///
    /// Run with:
    ///   cargo test -p spass generate_website_fixtures -- --nocapture --ignored
    #[test]
    #[ignore]
    fn generate_website_fixtures() {
        std::fs::create_dir_all(FIXTURE_DIR).unwrap();

        // 1. Minimal — 1 entry. Tests the smallest valid file the website can handle.
        SpassGenerator::new(FIXTURE_PASSWORD)
            .entry(TestEntry::new(
                "https://example.com",
                "user@example.com",
                "Hunter2!",
                "Example",
                "",
            ))
            .write_to_file(format!("{FIXTURE_DIR}/test_minimal.spass"));

        println!("wrote test_minimal.spass  (1 entry)");

        // 2. Small — 8 entries: clean entries + 1 missing URL (warning) + 1
        //    duplicate. Tests the warning and duplicate badges on the review page.
        SpassGenerator::new(FIXTURE_PASSWORD)
            .entries([
                TestEntry::new(
                    "https://accounts.google.com",
                    "user@gmail.com",
                    "G00gleP@ss!",
                    "Google",
                    "Main account",
                ),
                TestEntry::new(
                    "https://github.com",
                    "devuser",
                    "gh_abc123",
                    "GitHub",
                    "Work",
                ),
                TestEntry::new(
                    "https://netflix.com",
                    "stream@mail.com",
                    "Netfl1x!",
                    "Netflix",
                    "",
                ),
                TestEntry::new("https://github.com", "devuser", "gh_abc123", "GitHub", ""), // duplicate
                TestEntry::new(
                    "https://amazon.com",
                    "buyer@mail.com",
                    "Amaz0n#1",
                    "Amazon",
                    "Prime",
                ),
                TestEntry::new(
                    "https://linkedin.com",
                    "pro@mail.com",
                    "L1nked!n",
                    "LinkedIn",
                    "",
                ),
                TestEntry::new(
                    "",
                    "admin",
                    "Admin@1234",
                    "Unknown",
                    "missing url — warning",
                ),
                TestEntry::new(
                    "https://apple.com",
                    "me@icloud.com",
                    "AppleID_99!",
                    "Apple ID",
                    "Personal",
                ),
            ])
            .write_to_file(format!("{FIXTURE_DIR}/test_small.spass"));

        println!("wrote test_small.spass    (8 entries: clean, 1 duplicate, 1 warning)");

        // 3. Medium — 30 entries: realistic mix including Android app entries,
        //    entries with special characters in passwords, long URLs, and empty
        //    fields. Tests all table features at once.
        SpassGenerator::new(FIXTURE_PASSWORD)
            .entries([
                TestEntry::new(
                    "https://accounts.google.com",
                    "alice@gmail.com",
                    "G00gl3P@ss!",
                    "Google",
                    "Personal",
                ),
                TestEntry::new(
                    "https://accounts.google.com",
                    "alice@work.com",
                    "W0rkG00gle#2",
                    "Google (Work)",
                    "Work GSuite",
                ),
                TestEntry::new(
                    "https://github.com",
                    "alice-dev",
                    "gh_pat_abc123xyz",
                    "GitHub",
                    "",
                ),
                TestEntry::new(
                    "https://gitlab.com",
                    "alice-dev",
                    "glpat-xyz789",
                    "GitLab",
                    "Self-hosted",
                ),
                TestEntry::new(
                    "https://netflix.com",
                    "alice@gmail.com",
                    "Netfl1x#Stream",
                    "Netflix",
                    "",
                ),
                TestEntry::new(
                    "https://spotify.com",
                    "alice@gmail.com",
                    "Sp0tify!Premium",
                    "Spotify",
                    "",
                ),
                TestEntry::new(
                    "https://amazon.com",
                    "alice@gmail.com",
                    "Am@z0nPrime24",
                    "Amazon",
                    "Prime",
                ),
                TestEntry::new(
                    "https://paypal.com",
                    "alice@gmail.com",
                    "P@yP@l2024!",
                    "PayPal",
                    "",
                ),
                TestEntry::new(
                    "https://apple.com",
                    "alice@icloud.com",
                    "AppleID_Secure99!",
                    "Apple ID",
                    "Personal",
                ),
                TestEntry::new(
                    "https://microsoft.com",
                    "alice@outlook.com",
                    "M1cr0s0ft#Office",
                    "Microsoft",
                    "Office 365",
                ),
                TestEntry::new(
                    "https://dropbox.com",
                    "alice@gmail.com",
                    "Dr0pb0x_Cloud!",
                    "Dropbox",
                    "",
                ),
                TestEntry::new(
                    "https://notion.so",
                    "alice@work.com",
                    "N0t10n#Team",
                    "Notion",
                    "Work",
                ),
                TestEntry::new(
                    "https://slack.com",
                    "alice@work.com",
                    "Sl@ck_Work2024",
                    "Slack",
                    "",
                ),
                TestEntry::new(
                    "https://figma.com",
                    "alice@work.com",
                    "F1gma#Design",
                    "Figma",
                    "",
                ),
                TestEntry::new(
                    "https://linear.app",
                    "alice@work.com",
                    "L1n3ar!Issues",
                    "Linear",
                    "",
                ),
                TestEntry::new(
                    "https://vercel.com",
                    "alice-dev",
                    "Vercel_Deploy#1",
                    "Vercel",
                    "",
                ),
                TestEntry::new(
                    "https://cloudflare.com",
                    "alice-dev",
                    "CF_W0rker$2024",
                    "Cloudflare",
                    "",
                ),
                TestEntry::new(
                    "https://bankofamerica.com",
                    "",
                    "B0fA_Secure#9!",
                    "Bank of America",
                    "missing username",
                ),
                TestEntry::new(
                    "",
                    "admin",
                    "Admin@1234",
                    "Internal Dashboard",
                    "missing url",
                ),
                TestEntry::new(
                    "https://long-subdomain.enterprise-portal.internal.company.example.com",
                    "alice@company.com",
                    "Corp0rate!Pass1",
                    "Work Portal",
                    "Long URL",
                ),
                TestEntry::new(
                    "android://com.google.android.gm",
                    "alice@gmail.com",
                    "GmailApp!Pass",
                    "Gmail App",
                    "",
                ),
                TestEntry::new(
                    "android://com.netflix.mediaclient",
                    "alice@gmail.com",
                    "Netfl1x!",
                    "Netflix App",
                    "",
                ),
                TestEntry::new(
                    "android://com.spotify.music",
                    "alice@gmail.com",
                    "Sp0tify!",
                    "Spotify App",
                    "",
                ),
                TestEntry::new(
                    "android://com.samsung.android.app.samsungpay",
                    "alice@gmail.com",
                    "SPayP@ss9",
                    "Samsung Pay",
                    "",
                ),
                TestEntry::new(
                    "android://com.robinhood.android",
                    "alice@gmail.com",
                    "R0b1nhood#Trade",
                    "Robinhood",
                    "Brokerage",
                ),
                TestEntry::new(
                    "https://github.com",
                    "alice-dev",
                    "gh_pat_abc123xyz",
                    "GitHub",
                    "",
                ), // duplicate of row 3
                TestEntry::new(
                    "https://twitter.com",
                    "alice_x",
                    "p@ssw0rd,with,commas",
                    "X / Twitter",
                    "has commas in password",
                ),
                TestEntry::new(
                    "https://reddit.com",
                    "u/alice",
                    "R3ddit#2024!",
                    "Reddit",
                    "",
                ),
                TestEntry::new(
                    "https://discord.com",
                    "alice#1234",
                    "D1sc0rd!Server",
                    "Discord",
                    "Gaming",
                ),
                TestEntry::new(
                    "https://twitch.tv",
                    "alicestreams",
                    "Tw1tch#Stream24",
                    "Twitch",
                    "",
                ),
            ])
            .write_to_file(format!("{FIXTURE_DIR}/test_medium.spass"));

        println!("wrote test_medium.spass   (30 entries: android apps, warnings, duplicates, special chars, long URL)");

        // 4. Large — 120 entries. Tests scrolling, filter performance, and bulk
        //    operations on the review page.
        let mut gen = SpassGenerator::new(FIXTURE_PASSWORD);
        let domains = [
            "google.com",
            "github.com",
            "amazon.com",
            "netflix.com",
            "spotify.com",
            "apple.com",
            "microsoft.com",
            "dropbox.com",
            "notion.so",
            "slack.com",
            "figma.com",
            "linear.app",
            "vercel.com",
            "cloudflare.com",
            "twitter.com",
            "reddit.com",
            "discord.com",
            "twitch.tv",
            "linkedin.com",
            "facebook.com",
        ];
        for i in 0..120usize {
            let domain = domains[i % domains.len()];
            let url = if i % 15 == 0 {
                String::new() // warning: missing url every 15 entries
            } else {
                format!("https://{domain}")
            };
            let username = if i % 20 == 0 {
                String::new() // warning: missing username every 20 entries
            } else {
                format!("user{i}@mail.com")
            };
            // Every 10th entry is a duplicate of the previous one
            let suffix = if i % 10 == 9 { i - 1 } else { i };
            gen = gen.entry(TestEntry::new(
                url,
                username,
                format!("Pass#{suffix}!Secure"),
                format!("Account {i:03}"),
                if i % 3 == 0 {
                    format!("note for entry {i}")
                } else {
                    String::new()
                },
            ));
        }
        gen.write_to_file(format!("{FIXTURE_DIR}/test_large.spass"));

        println!("wrote test_large.spass    (120 entries: bulk data, warnings, duplicates)");
        println!("\nPassword for all fixtures: {FIXTURE_PASSWORD}");
    }

    /// Generates a 1 000 000-entry `.spass` fixture into `tmp/`.
    ///
    /// Run with:
    ///   cargo test -p spass generate_1m_fixture -- --nocapture --ignored
    #[test]
    #[ignore]
    fn generate_1m_fixture() {
        use std::time::Instant;

        std::fs::create_dir_all(FIXTURE_DIR).unwrap();

        const N: usize = 1_000_000;

        let domains = [
            "google.com",
            "github.com",
            "amazon.com",
            "netflix.com",
            "spotify.com",
            "apple.com",
            "microsoft.com",
            "dropbox.com",
            "notion.so",
            "slack.com",
            "figma.com",
            "linear.app",
            "vercel.com",
            "cloudflare.com",
            "twitter.com",
            "reddit.com",
            "discord.com",
            "twitch.tv",
            "linkedin.com",
            "facebook.com",
            "paypal.com",
            "stripe.com",
            "shopify.com",
            "airbnb.com",
            "uber.com",
            "lyft.com",
            "zoom.us",
            "atlassian.com",
            "salesforce.com",
            "adobe.com",
        ];

        println!("Building {N} entries…");
        let build_start = Instant::now();

        let mut gen = SpassGenerator::new(FIXTURE_PASSWORD);

        for i in 0..N {
            let domain = domains[i % domains.len()];

            let url = if i % 200 == 0 {
                String::new() // 0.5 % missing-URL warnings
            } else {
                format!("https://{domain}")
            };

            let username = if i % 300 == 0 {
                String::new() // 0.33 % missing-username warnings
            } else {
                format!("user{i}@{domain}")
            };

            // Every 50th entry duplicates the previous one (same url + username).
            let dup_i = if i % 50 == 49 { i - 1 } else { i };
            let dup_domain = domains[dup_i % domains.len()];
            let dup_url = format!("https://{dup_domain}");
            let dup_username = format!("user{dup_i}@{dup_domain}");

            let (final_url, final_username) = if i % 50 == 49 {
                (dup_url, dup_username)
            } else {
                (url, username)
            };

            gen = gen.entry(TestEntry::new(
                final_url,
                final_username,
                format!("P@ss#{i:07}!Sec"),
                format!("Account {i:07}"),
                if i % 5 == 0 {
                    format!("note {i}")
                } else {
                    String::new()
                },
            ));
        }

        println!("Entries built in {:.2?}", build_start.elapsed());

        println!("Encrypting with {FIXTURE_PASSWORD:?} (70 000 PBKDF2 iterations)…");
        let enc_start = Instant::now();

        gen.write_to_file(format!("{FIXTURE_DIR}/test_1m.spass"));

        let elapsed = enc_start.elapsed();
        let path = format!("{FIXTURE_DIR}/test_1m.spass");
        let size_mb = std::fs::metadata(&path).unwrap().len() as f64 / 1_048_576.0;

        println!("Encrypted in {elapsed:.2?}");
        println!("wrote test_1m.spass       ({N} entries, {size_mb:.1} MB)");
        println!("Password: {FIXTURE_PASSWORD}");
    }

    fn pipeline() -> DecryptionPipeline {
        // Use a low iteration count so tests run fast.
        DecryptionPipeline::new(1_000)
    }

    fn generator() -> SpassGenerator {
        // Low iterations to match the pipeline above.
        SpassGenerator {
            password: TEST_PASSWORD.to_string(),
            entries: Vec::new(),
            salt: Some([0x01; 20]),
            iv: Some([0x02; 16]),
        }
    }

    fn generate_low_iter(gen: &SpassGenerator) -> String {
        let salt = gen.salt.unwrap();
        let iv = gen.iv.unwrap();
        let plaintext = gen.build_plaintext();
        let ciphertext = SpassGenerator::encrypt_with_iterations(
            plaintext.as_bytes(),
            &gen.password,
            &salt,
            &iv,
            1_000,
        );
        let mut blob = Vec::with_capacity(36 + ciphertext.len());
        blob.extend_from_slice(&salt);
        blob.extend_from_slice(&iv);
        blob.extend_from_slice(&ciphertext);
        general_purpose::STANDARD.encode(&blob)
    }

    #[test]
    fn round_trips_single_entry() {
        let gen = generator().entry(TestEntry::new(
            "https://example.com",
            "user@example.com",
            "secret",
            "Example",
            "test note",
        ));

        let content = generate_low_iter(&gen);
        let pw = EntryPassword::new(TEST_PASSWORD.to_string());
        let collection = pipeline().decrypt_string(&content, &pw).unwrap();

        assert_eq!(collection.len(), 1);
        let entry = &collection.entries()[0];
        assert_eq!(entry.url.as_str(), "https://example.com");
        assert_eq!(entry.username.as_str(), "user@example.com");
        assert_eq!(entry.password.as_str(), "secret");
        assert_eq!(entry.name.as_str(), "Example");
        assert_eq!(entry.note.as_str(), "test note");
    }

    #[test]
    fn round_trips_multiple_entries() {
        let gen = generator()
            .entry(TestEntry::new("https://a.com", "alice", "pass1", "A", ""))
            .entry(TestEntry::new("https://b.com", "bob", "pass2", "B", "note"))
            .entry(TestEntry::new(
                "android://com.example",
                "charlie",
                "pass3",
                "App",
                "",
            ));

        let content = generate_low_iter(&gen);
        let pw = EntryPassword::new(TEST_PASSWORD.to_string());
        let collection = pipeline().decrypt_string(&content, &pw).unwrap();

        assert_eq!(collection.len(), 3);
        assert_eq!(collection.entries()[1].username.as_str(), "bob");
    }

    #[test]
    fn wrong_password_returns_error() {
        let gen = generator().entry(TestEntry::new("https://x.com", "u", "p", "X", ""));
        let content = generate_low_iter(&gen);
        let pw = EntryPassword::new("wrong_password".to_string());
        assert!(pipeline().decrypt_string(&content, &pw).is_err());
    }

    #[test]
    fn entry_with_comma_in_field_round_trips() {
        let gen = generator().entry(TestEntry::new(
            "https://example.com",
            "user@email.com",
            "pass,with,commas",
            "Site, Inc.",
            "has, commas",
        ));

        let content = generate_low_iter(&gen);
        let pw = EntryPassword::new(TEST_PASSWORD.to_string());
        let collection = pipeline().decrypt_string(&content, &pw).unwrap();

        assert_eq!(
            collection.entries()[0].password.as_str(),
            "pass,with,commas"
        );
        assert_eq!(collection.entries()[0].name.as_str(), "Site, Inc.");
    }
}
