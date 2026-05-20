use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A hex-encoded string produced by `to_hex()` on cryptographic byte
/// types. Keeps hex strings distinct from arbitrary `String` values
/// at call sites so a logger or `Display` impl can't accidentally
/// confuse the two.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hex(String);

impl Hex {
    pub(crate) fn encode(bytes: &[u8]) -> Self {
        Hex(hex::encode(bytes))
    }

    /// Borrow the underlying string.
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
    /// Trims surrounding whitespace from `url` and stores the
    /// remainder.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn new(url: String) -> Self {
        Url(url.trim().to_string())
    }

    /// Borrow the trimmed URL.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Extracts the host from HTTP/HTTPS URLs. Returns `None` for
    /// `android://` and other schemes -- Samsung Pass stores those
    /// for native-app credentials, and we don't try to surface a
    /// "domain" out of them.
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
    /// Trims surrounding whitespace from `username` and stores the
    /// remainder.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn new(username: String) -> Self {
        Username(username.trim().to_string())
    }

    /// Borrow the trimmed username.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Cheap heuristic: contains `@` and `.`. Useful for picking a
    /// "username vs email" display style; not for validating
    /// real email addresses.
    #[must_use]
    pub fn is_email(&self) -> bool {
        self.0.contains('@') && self.0.contains('.')
    }
}

/// A password value. Zeroized on drop. The `Debug` impl prints a
/// length-only placeholder so accidental logging doesn't leak the
/// secret.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EntryPassword(String);

impl EntryPassword {
    /// Wraps `password` without trimming (passwords may legitimately
    /// contain leading or trailing whitespace).
    #[must_use]
    pub fn new(password: String) -> Self {
        EntryPassword(password)
    }

    /// # Security
    ///
    /// Do not log, display, or store the returned slice beyond the
    /// lifetime of this value -- the outer [`EntryPassword`] is
    /// zeroized on drop, but a copy you made out of the slice is not.
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
    /// Trims surrounding whitespace from `name` and stores the
    /// remainder.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn new(name: String) -> Self {
        EntryName(name.trim().to_string())
    }

    /// Borrow the trimmed name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A note attached to a password entry. Whitespace is trimmed on
/// construction.
#[derive(Debug, Clone)]
pub struct Note(String);

impl Note {
    /// Trims surrounding whitespace from `note` and stores the
    /// remainder.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn new(note: String) -> Self {
        Note(note.trim().to_string())
    }

    /// Borrow the trimmed note.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Raw decrypted bytes from a `.spass` file. Zeroized on drop. The
/// `Debug` impl prints a length-only placeholder so accidental
/// logging doesn't dump the decrypted payload.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DecryptedData(Box<[u8]>);

impl DecryptedData {
    /// Wraps `data` and takes ownership of its allocation.
    #[must_use]
    pub fn new(data: Vec<u8>) -> Self {
        DecryptedData(data.into_boxed_slice())
    }

    /// Borrow the decrypted bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Length of the decrypted payload, in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// `true` when the decrypted payload is zero bytes.
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
