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
    /// Construct a test entry. Each field takes anything `Into<String>`
    /// (`&str`, `String`, `Cow<'_, str>`) so call sites stay concise.
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
    /// Plaintext format version to emit. Defaults to v30 so existing callers
    /// don't need to touch their code; flip to v31 with `.with_version()`.
    version: crate::format::SpassFormatVersion,
}

impl SpassGenerator {
    /// Start a generator that will encrypt the produced `.spass`
    /// blob with `password`. No entries, random salt/IV, v30 format
    /// until reconfigured.
    pub fn new(password: impl Into<String>) -> Self {
        Self {
            password: password.into(),
            entries: Vec::new(),
            salt: None,
            iv: None,
            version: crate::format::SpassFormatVersion::V30,
        }
    }

    /// Selects the plaintext format version. Default is `V30`.
    #[must_use]
    pub fn with_version(mut self, version: crate::format::SpassFormatVersion) -> Self {
        self.version = version;
        self
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
        match self.version {
            crate::format::SpassFormatVersion::V30 => self.build_plaintext_v30(),
            crate::format::SpassFormatVersion::V31 => self.build_plaintext_v31(),
        }
    }

    fn build_plaintext_v30(&self) -> String {
        let mut out = String::new();
        // Line 1: format version sentinel. Samsung emits `spass_export_v1`
        // verbatim for v30 - keep this exact string.
        out.push_str("spass_export_v1\n");
        // Line 2: Samsung internal header section (ignored by the parser).
        out.push_str("generated_by_testkit\n");
        // Line 3: section separator.
        out.push_str("next_table\n");
        // Lines 4+: password CSV.
        out.push_str("URL,Username,Password,Name,Note\n");
        for entry in &self.entries {
            out.push_str(&entry.to_csv_row());
            out.push('\n');
        }
        out
    }

    fn build_plaintext_v31(&self) -> String {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

        const COL_ORIGIN_URL: usize = 1;
        const COL_USERNAME_VALUE: usize = 4;
        const COL_PASSWORD_VALUE: usize = 7;
        const COL_TITLE: usize = 17;
        const COL_CREDENTIAL_MEMO: usize = 31;
        const ABSENT_SENTINEL_B64: &str = "JiYmTlVMTCYmJg=="; // Base64("&&&NULL&&&")

        // 35-column header in canonical order.
        let header_cols: [&str; 35] = [
            "_id",
            "origin_url",
            "action_url",
            "username_element",
            "username_value",
            "id_tz_enc",
            "password_element",
            "password_value",
            "pw_tz_enc",
            "host_url",
            "ssl_valid",
            "preferred",
            "blacklisted_by_user",
            "use_additional_auth",
            "cm_api_support",
            "created_time",
            "modified_time",
            "title",
            "favicon",
            "source_type",
            "app_name",
            "package_name",
            "package_signature",
            "reserved_1",
            "reserved_2",
            "reserved_3",
            "reserved_4",
            "reserved_5",
            "reserved_6",
            "reserved_7",
            "reserved_8",
            "credential_memo",
            "otp",
            "root_id",
            "parent_id",
        ];

        let mut out = String::new();
        // Line 1: version sentinel.
        out.push_str("31\n");
        // Line 2: 4-bool metadata flags.
        out.push_str("true;false;false;false\n");
        // Line 3: extra metadata bool (new in v31).
        out.push_str("false\n");
        // Line 4: section separator.
        out.push_str("next_table\n");
        // Line 5: 35-column header.
        out.push_str(&header_cols.join(";"));
        out.push('\n');
        // Lines 6+: data rows.
        for (idx, entry) in self.entries.iter().enumerate() {
            let mut parts: Vec<String> = (0..35).map(|_| String::new()).collect();
            // _id is just the row's 1-based index encoded as Base64.
            parts[0] = BASE64.encode((idx + 1).to_string().as_bytes());
            parts[COL_ORIGIN_URL] = BASE64.encode(entry.url.as_bytes());
            parts[COL_USERNAME_VALUE] = BASE64.encode(entry.username.as_bytes());
            parts[COL_PASSWORD_VALUE] = BASE64.encode(entry.password.as_bytes());
            parts[COL_TITLE] = BASE64.encode(entry.name.as_bytes());
            // Empty-note round-trips as the absent sentinel so v31 fixtures
            // exercise the same path Samsung's exports do.
            parts[COL_CREDENTIAL_MEMO] = if entry.note.is_empty() {
                ABSENT_SENTINEL_B64.to_string()
            } else {
                BASE64.encode(entry.note.as_bytes())
            };
            out.push_str(&parts.join(";"));
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
    /// Generator pre-loaded with a realistic set of test entries
    /// (Google, Apple, GitHub, etc.). Useful as a starting point
    /// for tests that don't care about the exact contents.
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

    /// Directory for the per-version website-test fixtures, tracked in git
    /// under `spass-core/gen-test/{v30,v31}/`. Each fixture is small (a few
    /// KB each); the 1M-entry stress fixture lives separately because it's
    /// too big to commit. Resolved relative to this crate's manifest so the
    /// path works on any machine.
    const FIXTURE_DIR_V30: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../gen-test/v30");
    const FIXTURE_DIR_V31: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../gen-test/v31");

    // The 1M-entry stress fixtures (~100-200 MB each) live alongside the
    // small fixtures under `gen-test/{v30,v31}/test05-1m.spass`. They are
    // gitignored at the spass-core level (see `.gitignore`).

    /// Generates 4 v30-format `.spass` fixture files into
    /// `spass-core/gen-test/v30/` for manual website / iOS / CLI testing.
    ///
    /// Run with:
    ///   cargo test -p spass generate_website_fixtures -- --nocapture --ignored
    #[test]
    #[ignore]
    fn generate_website_fixtures() {
        std::fs::create_dir_all(FIXTURE_DIR_V30).unwrap();

        // 1. Minimal — 1 entry. Tests the smallest valid file the website can handle.
        SpassGenerator::new(FIXTURE_PASSWORD)
            .entry(TestEntry::new(
                "https://example.com",
                "user@example.com",
                "Hunter2!",
                "Example",
                "",
            ))
            .write_to_file(format!("{FIXTURE_DIR_V30}/test01-minimal.spass"));

        println!("wrote v30/test01-minimal.spass  (1 entry)");

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
            .write_to_file(format!("{FIXTURE_DIR_V30}/test02-small.spass"));

        println!("wrote v30/test02-small.spass    (8 entries: clean, 1 duplicate, 1 warning)");

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
            .write_to_file(format!("{FIXTURE_DIR_V30}/test03-medium.spass"));

        println!("wrote v30/test03-medium.spass   (30 entries: android apps, warnings, duplicates, special chars, long URL)");

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
        gen.write_to_file(format!("{FIXTURE_DIR_V30}/test04-large.spass"));

        println!("wrote v30/test04-large.spass    (120 entries: bulk data, warnings, duplicates)");
        println!("\nPassword for all fixtures: {FIXTURE_PASSWORD}");
    }

    /// Generates 4 v31-format `.spass` fixture files into
    /// `spass-core/gen-test/v31/` for manual website / iOS / CLI testing.
    ///
    /// Entries are clean (no warnings / duplicates) -- the v31 generator
    /// exercises the new wire format (35 columns, semicolons, Base64,
    /// `&&&NULL&&&` sentinel) rather than re-covering the website's quirk
    /// matrix that the v30 fixtures already cover.
    ///
    /// Run with:
    ///   cargo test -p spass generate_website_fixtures_v31 -- --nocapture --ignored
    #[test]
    #[ignore]
    fn generate_website_fixtures_v31() {
        use crate::format::SpassFormatVersion;

        std::fs::create_dir_all(FIXTURE_DIR_V31).unwrap();

        let make_entries = |n: usize| -> Vec<TestEntry> {
            (0..n)
                .map(|i| {
                    TestEntry::new(
                        format!("https://example{i}.com"),
                        format!("user{i}@mail.com"),
                        format!("password{i}"),
                        format!("Site {i:03}"),
                        if i % 4 == 0 {
                            // exercises `&&&NULL&&&` sentinel mapping (testkit
                            // emits it for empty notes when version is V31)
                            String::new()
                        } else {
                            format!("note for entry {i}")
                        },
                    )
                })
                .collect()
        };

        let configs = [
            ("test01-minimal", 1),
            ("test02-small", 8),
            ("test03-medium", 30),
            ("test04-large", 120),
        ];

        for (name, n) in configs {
            let entries = make_entries(n);
            SpassGenerator::new(FIXTURE_PASSWORD)
                .with_version(SpassFormatVersion::V31)
                .entries(entries)
                .write_to_file(format!("{FIXTURE_DIR_V31}/{name}.spass"));
            println!("wrote v31/{name}.spass  ({n} entries)");
        }

        println!("\nPassword for all v31 fixtures: {FIXTURE_PASSWORD}");
    }

    /// Generates a 1 000 000-entry v30 `.spass` fixture at
    /// `spass-core/gen-test/v30/test05-1m.spass`. The output is ~100 MB and
    /// gitignored.
    ///
    /// Run with:
    ///   cargo test -p spass generate_1m_fixture -- --nocapture --ignored
    #[test]
    #[ignore]
    fn generate_1m_fixture() {
        use std::time::Instant;

        std::fs::create_dir_all(FIXTURE_DIR_V30).unwrap();

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

        gen.write_to_file(format!("{FIXTURE_DIR_V30}/test05-1m.spass"));

        let elapsed = enc_start.elapsed();
        let path = format!("{FIXTURE_DIR_V30}/test05-1m.spass");
        let size_mb = std::fs::metadata(&path).unwrap().len() as f64 / 1_048_576.0;

        println!("Encrypted in {elapsed:.2?}");
        println!("wrote v30/test05-1m.spass ({N} entries, {size_mb:.1} MB)");
        println!("Password: {FIXTURE_PASSWORD}");
    }

    /// Generates a 1 000 000-entry v31 `.spass` fixture at
    /// `spass-core/gen-test/v31/test05-1m.spass`. The output is ~200 MB
    /// (Base64 + 35 columns roughly doubles v30's wire size) and gitignored.
    ///
    /// Run with:
    ///   cargo test -p spass generate_1m_fixture_v31 -- --nocapture --ignored
    #[test]
    #[ignore]
    fn generate_1m_fixture_v31() {
        use crate::format::SpassFormatVersion;
        use std::time::Instant;

        std::fs::create_dir_all(FIXTURE_DIR_V31).unwrap();

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
        ];

        println!("Building {N} entries…");
        let build_start = Instant::now();

        let mut gen = SpassGenerator::new(FIXTURE_PASSWORD).with_version(SpassFormatVersion::V31);

        for i in 0..N {
            let domain = domains[i % domains.len()];
            gen = gen.entry(TestEntry::new(
                format!("https://{domain}"),
                format!("user{i}@{domain}"),
                format!("P@ss#{i:07}!Sec"),
                format!("Account {i:07}"),
                if i % 5 == 0 {
                    format!("note {i}")
                } else {
                    // empty -> exercises &&&NULL&&& sentinel emission for v31
                    String::new()
                },
            ));
        }

        println!("Entries built in {:.2?}", build_start.elapsed());
        println!("Encrypting with {FIXTURE_PASSWORD:?} (70 000 PBKDF2 iterations)…");
        let enc_start = Instant::now();

        let path = format!("{FIXTURE_DIR_V31}/test05-1m.spass");
        gen.write_to_file(&path);

        let elapsed = enc_start.elapsed();
        let size_mb = std::fs::metadata(&path).unwrap().len() as f64 / 1_048_576.0;

        println!("Encrypted in {elapsed:.2?}");
        println!("wrote v31/test05-1m.spass ({N} entries, {size_mb:.1} MB)");
        println!("Password: {FIXTURE_PASSWORD}");
    }

    /// Generates a 30-entry v30 `.spass` fixture at
    /// `spass-core/gen-test/v30/demo.spass`. Used for the SPASSPort product
    /// page screenshots, App Store screenshots, and demo videos. Every URL
    /// maps to a brand the iOS app has a bundled favicon for, so every row
    /// renders with a real-looking icon instead of the first-letter-circle
    /// fallback.
    ///
    /// The data follows a single persona ("Alex Morgan") with both personal
    /// (gmail / icloud / outlook) and work (northwindlabs.com) accounts.
    /// Every entry shares the same per-entry password (`ENTRY_PASSWORD`
    /// below) - this is a product-page demo, not a real vault, so per-entry
    /// password variety isn't load-bearing.
    ///
    /// File-decryption password: `TestPassword123` (the standard fixture
    /// password; matches what App Store review notes will document).
    ///
    /// Run with:
    ///   cargo test -p spass generate_demo_fixture -- --nocapture --ignored
    #[test]
    #[ignore]
    fn generate_demo_fixture() {
        std::fs::create_dir_all(FIXTURE_DIR_V30).unwrap();

        // Shared password for every entry. Looks like a real personal
        // password someone might pick; obviously a demo when seen in the
        // context of a product page.
        const ENTRY_PASSWORD: &str = "MorganFamily!2026";

        // 30 entries across the top 15 brands the iOS favicon directory
        // covers. Two entries per brand: usually personal + work, sometimes
        // personal + secondary identity. URLs are real Samsung-Pass-style
        // subdomains; the cascading favicon lookup strips them down to the
        // base domain match.
        let entries = vec![
            // 1-2 Google
            TestEntry::new(
                "https://accounts.google.com",
                "alex.morgan@gmail.com",
                ENTRY_PASSWORD,
                "Google",
                "",
            ),
            TestEntry::new(
                "https://workspace.google.com",
                "a.morgan@northwindlabs.com",
                ENTRY_PASSWORD,
                "Google Workspace",
                "2FA via Authenticator",
            ),
            // 3-4 Apple
            TestEntry::new(
                "https://appleid.apple.com",
                "alex.morgan@icloud.com",
                ENTRY_PASSWORD,
                "Apple ID",
                "",
            ),
            TestEntry::new(
                "https://developer.apple.com",
                "alex.morgan@gmail.com",
                ENTRY_PASSWORD,
                "Apple Developer",
                "Team ID: ABCD1234",
            ),
            // 5-6 Microsoft
            TestEntry::new(
                "https://login.microsoft.com",
                "alex.morgan@outlook.com",
                ENTRY_PASSWORD,
                "Microsoft 365",
                "",
            ),
            TestEntry::new(
                "https://portal.microsoft.com",
                "a.morgan@northwindlabs.com",
                ENTRY_PASSWORD,
                "Microsoft Azure",
                "",
            ),
            // 7-8 Amazon
            TestEntry::new(
                "https://amazon.com",
                "alex.morgan@gmail.com",
                ENTRY_PASSWORD,
                "Amazon",
                "Prime household",
            ),
            TestEntry::new(
                "https://aws.amazon.com",
                "aws-amorgan@northwindlabs.com",
                ENTRY_PASSWORD,
                "Amazon Web Services",
                "IAM user, MFA enforced",
            ),
            // 9-10 Netflix
            TestEntry::new(
                "https://netflix.com",
                "alex.morgan@gmail.com",
                ENTRY_PASSWORD,
                "Netflix",
                "Family plan",
            ),
            TestEntry::new(
                "https://netflix.com",
                "alex.morgan.uk@gmail.com",
                ENTRY_PASSWORD,
                "Netflix UK",
                "",
            ),
            // 11-12 Spotify
            TestEntry::new(
                "https://accounts.spotify.com",
                "alex.morgan@gmail.com",
                ENTRY_PASSWORD,
                "Spotify",
                "",
            ),
            TestEntry::new(
                "https://podcasters.spotify.com",
                "podcasts@morganmedia.fm",
                ENTRY_PASSWORD,
                "Spotify for Podcasters",
                "",
            ),
            // 13-14 GitHub
            TestEntry::new(
                "https://github.com",
                "alexmorgan",
                ENTRY_PASSWORD,
                "GitHub",
                "Personal access token rotates Jan 2026",
            ),
            TestEntry::new(
                "https://github.com",
                "amorgan-northwind",
                ENTRY_PASSWORD,
                "GitHub Enterprise",
                "",
            ),
            // 15-16 Facebook
            TestEntry::new(
                "https://m.facebook.com",
                "alex.morgan@gmail.com",
                ENTRY_PASSWORD,
                "Facebook",
                "",
            ),
            TestEntry::new(
                "https://business.facebook.com",
                "alex.morgan@gmail.com",
                ENTRY_PASSWORD,
                "Meta Business",
                "",
            ),
            // 17-18 Instagram
            TestEntry::new(
                "https://www.instagram.com",
                "alex.morgan",
                ENTRY_PASSWORD,
                "Instagram",
                "",
            ),
            TestEntry::new(
                "https://www.instagram.com",
                "alex.morgan.photo",
                ENTRY_PASSWORD,
                "Instagram Creator",
                "",
            ),
            // 19-20 X
            TestEntry::new("https://x.com", "alexmorgan", ENTRY_PASSWORD, "X", ""),
            TestEntry::new(
                "https://x.com",
                "alex_morgan_pro",
                ENTRY_PASSWORD,
                "X Premium",
                "",
            ),
            // 21-22 LinkedIn
            TestEntry::new(
                "https://www.linkedin.com",
                "alex.morgan@gmail.com",
                ENTRY_PASSWORD,
                "LinkedIn",
                "",
            ),
            TestEntry::new(
                "https://recruiter.linkedin.com",
                "a.morgan@northwindlabs.com",
                ENTRY_PASSWORD,
                "LinkedIn Recruiter",
                "",
            ),
            // 23-24 Discord
            TestEntry::new(
                "https://discord.com",
                "alex.morgan#0001",
                ENTRY_PASSWORD,
                "Discord",
                "",
            ),
            TestEntry::new(
                "https://discord.com",
                "amorgan_dev",
                ENTRY_PASSWORD,
                "Discord (Dev Server)",
                "",
            ),
            // 25-26 Reddit
            TestEntry::new(
                "https://www.reddit.com",
                "alex_morgan",
                ENTRY_PASSWORD,
                "Reddit",
                "",
            ),
            TestEntry::new(
                "https://www.reddit.com",
                "alexm_premium",
                ENTRY_PASSWORD,
                "Reddit Premium",
                "",
            ),
            // 27-28 Slack
            TestEntry::new(
                "https://northwindlabs.slack.com",
                "alex.morgan@northwindlabs.com",
                ENTRY_PASSWORD,
                "Slack",
                "",
            ),
            TestEntry::new(
                "https://morgangroup.slack.com",
                "alex.morgan@morgangroup.com",
                ENTRY_PASSWORD,
                "Slack (Client Workspace)",
                "",
            ),
            // 29-30 Dropbox
            TestEntry::new(
                "https://www.dropbox.com",
                "alex.morgan@gmail.com",
                ENTRY_PASSWORD,
                "Dropbox",
                "",
            ),
            TestEntry::new(
                "https://www.dropbox.com",
                "team-amorgan@northwindlabs.com",
                ENTRY_PASSWORD,
                "Dropbox Business",
                "",
            ),
        ];

        assert_eq!(
            entries.len(),
            30,
            "demo fixture must have exactly 30 entries"
        );

        let path = format!("{FIXTURE_DIR_V30}/demo.spass");
        SpassGenerator::new(FIXTURE_PASSWORD)
            .entries(entries)
            .write_to_file(&path);

        let size_kb = std::fs::metadata(&path).unwrap().len() as f64 / 1024.0;
        println!("wrote v30/demo.spass (30 entries, {size_kb:.1} KB)");
        println!("File password:  {FIXTURE_PASSWORD}");
        println!("Entry password: {ENTRY_PASSWORD} (shared across all 30 entries)");
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
            version: crate::format::SpassFormatVersion::V30,
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
