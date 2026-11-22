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
