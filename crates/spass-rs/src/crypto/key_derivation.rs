use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::domain::{EntryPassword, SpassResult};
use crate::format::Salt;

/// PBKDF2-HMAC-SHA256 iteration count used by Samsung Pass when creating `.spass` exports.
///
/// This is a format constant, not a security recommendation. Decrypting a real
/// `.spass` file with any other value will produce garbage.
pub const PBKDF2_ITERATIONS: u32 = 70_000;

/// A 32-byte AES-256 key derived from a password. Zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DerivedKey {
    key: Box<[u8; 32]>,
}

impl DerivedKey {
    /// Borrow the 32-byte AES-256 key. Underlying buffer is
    /// zeroized on drop.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

/// PBKDF2-HMAC-SHA256 key derivation.
///
/// Decryption of a real `.spass` file requires
/// [`PBKDF2_ITERATIONS`] (70,000); the configurable iteration count
/// exists for tests that want a faster derivation. Default
/// constructor uses the format constant.
pub struct KeyDerivation {
    iterations: u32,
}

impl KeyDerivation {
    /// PBKDF2 deriver with `iterations` rounds. Prefer
    /// [`Self::default`] for production; this constructor exists for
    /// tests that want faster derivation.
    #[must_use]
    pub fn new(iterations: u32) -> Self {
        Self { iterations }
    }

    /// Derives a 32-byte AES-256 key from `password` and `salt`.
    ///
    /// # Errors
    ///
    /// `SpassError::Decryption` if the underlying PBKDF2-HMAC-SHA256
    /// implementation rejects the inputs. In practice this can only
    /// happen for pathological output lengths and never for the
    /// fixed 32-byte derivation here.
    pub fn derive_key(&self, password: &EntryPassword, salt: Salt<'_>) -> SpassResult<DerivedKey> {
        let mut key = Box::new([0u8; 32]);

        pbkdf2::<Hmac<Sha256>>(
            password.as_str().as_bytes(),
            salt.as_bytes(),
            self.iterations,
            key.as_mut(),
        )
        .map_err(|_| crate::domain::SpassError::Decryption("Key derivation failed".to_string()))?;

        Ok(DerivedKey { key })
    }
}

impl Default for KeyDerivation {
    fn default() -> Self {
        Self::new(PBKDF2_ITERATIONS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::DecodedFile;

    #[test]
    fn test_key_derivation() {
        let kd = KeyDerivation::new(1000);
        let password = EntryPassword::new("test_password".to_owned());

        let decoded = DecodedFile::builder().build();
        let result = kd.derive_key(&password, decoded.salt());
        assert!(result.is_ok());

        let key = result.unwrap();
        assert_eq!(key.as_bytes().len(), 32);
    }
}
