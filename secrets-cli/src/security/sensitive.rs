use secrecy::{ExposeSecret, Secret};
use zeroize::Zeroize;

/// A sensitive string that gets zeroed on drop
pub type SensitiveString = Secret<String>;

/// A sensitive 32-byte key that gets zeroed on drop
#[derive(Clone)]
pub struct SecretKey {
    key: Secret<[u8; 32]>,
}

impl SecretKey {
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            key: Secret::new(key),
        }
    }

    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() != 32 {
            return None;
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(slice);
        Some(Self::new(key))
    }

    pub fn expose(&self) -> &[u8; 32] {
        self.key.expose_secret()
    }

    /// Generate a random key
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        Self::new(key)
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        // Secret already handles zeroize, but we can be extra safe
    }
}

/// Zeroize a mutable byte slice
#[allow(dead_code)] // Reserved for manual memory cleanup
pub fn zeroize_slice(slice: &mut [u8]) {
    slice.zeroize();
}
