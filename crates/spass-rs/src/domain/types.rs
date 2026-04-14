use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A hex-encoded string produced by `to_hex()` on cryptographic byte types.
///
/// Keeps hex strings distinct from arbitrary `String` values at call sites.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hex(String);

impl Hex {
    pub(crate) fn encode(bytes: &[u8]) -> Self {
        Hex(hex::encode(bytes))
    }

    /// Returns the hex string as a `&str`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Hex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<Hex> for String {
    fn from(h: Hex) -> Self {
        h.0
    }
}

/// URL for a password entry. Whitespace is trimmed on construction.
#[derive(Debug, Clone)]
pub struct Url(String);

impl Url {
    /// Constructs a `Url`, trimming surrounding whitespace.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn new(url: String) -> Self {
        Url(url.trim().to_string())
    }

    /// Returns the URL as a `&str`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Extracts the host from HTTP/HTTPS URLs. Returns `None` for `android://` and other schemes.
    #[must_use]
    pub fn domain(&self) -> Option<String> {
        if self.0.starts_with("http://") || self.0.starts_with("https://") {
            let url = &self.0;
            let start = url.find("://")?;
            let after_protocol = &url[start + 3..];
            if let Some(end) = after_protocol.find('/') {
                Some(after_protocol[..end].to_string())
            } else {
                Some(after_protocol.to_string())
            }
        } else {
            None
        }
    }
}

/// Username for a password entry. Whitespace is trimmed on construction.
#[derive(Debug, Clone)]
pub struct Username(String);

impl Username {
    /// Constructs a `Username`, trimming surrounding whitespace.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn new(username: String) -> Self {
        Username(username.trim().to_string())
    }

    /// Returns the username as a `&str`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns `true` if the username contains `@` and `.`, i.e. looks like an email.
    #[must_use]
    pub fn is_email(&self) -> bool {
        self.0.contains('@') && self.0.contains('.')
    }
}

/// A password value. Zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EntryPassword(String);

impl EntryPassword {
    /// Constructs an `EntryPassword`.
    #[must_use]
    pub fn new(password: String) -> Self {
        EntryPassword(password)
    }

    /// Returns the password as a `&str`.
    ///
    /// # Security
    ///
    /// Do not log, display, or store the returned slice beyond the lifetime of this value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for EntryPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<password:{} chars>", self.0.len())
    }
}

/// Entry display name. Whitespace is trimmed on construction.
#[derive(Debug, Clone)]
pub struct EntryName(String);

impl EntryName {
    /// Constructs an `EntryName`, trimming surrounding whitespace.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn new(name: String) -> Self {
        EntryName(name.trim().to_string())
    }

    /// Returns the name as a `&str`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A note attached to a password entry. Whitespace is trimmed on construction.
#[derive(Debug, Clone)]
pub struct Note(String);

impl Note {
    /// Constructs a `Note`, trimming surrounding whitespace.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn new(note: String) -> Self {
        Note(note.trim().to_string())
    }

    /// Returns the note as a `&str`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Raw decrypted bytes from a `.spass` file. Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DecryptedData(Box<[u8]>);

impl DecryptedData {
    /// Constructs `DecryptedData` from a `Vec<u8>`.
    #[must_use]
    pub fn new(data: Vec<u8>) -> Self {
        DecryptedData(data.into_boxed_slice())
    }

    /// Returns the decrypted bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the byte length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if there are no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for DecryptedData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DecryptedData({} bytes)", self.0.len())
    }
}
