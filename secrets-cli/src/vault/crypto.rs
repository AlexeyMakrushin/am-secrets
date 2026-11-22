use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::Sha256;

use crate::errors::{Result, SecretsError};
use crate::security::SecretKey;

const PBKDF2_ITERATIONS: u32 = 600_000;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

/// Derive a key from password using PBKDF2-SHA256
pub fn derive_key(password: &str, salt: &[u8]) -> SecretKey {
    let mut key = [0u8; KEY_LEN];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key);
    SecretKey::new(key)
}

/// Encrypt data with AES-256-GCM
/// Output format: salt (16) + nonce (12) + ciphertext
pub fn encrypt(data: &[u8], password: &str) -> Result<Vec<u8>> {
    // Generate random salt and nonce
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    // Derive key
    let key = derive_key(password, &salt);

    // Create cipher
    let cipher = Aes256Gcm::new_from_slice(key.expose())
        .map_err(|e| SecretsError::EncryptionFailed(e.to_string()))?;

    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt
    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|e| SecretsError::EncryptionFailed(e.to_string()))?;

    // Combine salt + nonce + ciphertext
    let mut result = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    result.extend_from_slice(&salt);
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt data encrypted with encrypt()
/// Input format: salt (16) + nonce (12) + ciphertext
pub fn decrypt(encrypted: &[u8], password: &str) -> Result<Vec<u8>> {
    if encrypted.len() < SALT_LEN + NONCE_LEN + 16 {
        // 16 is minimum GCM tag size
        return Err(SecretsError::VaultCorrupted);
    }

    // Extract salt, nonce, ciphertext
    let salt = &encrypted[..SALT_LEN];
    let nonce_bytes = &encrypted[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ciphertext = &encrypted[SALT_LEN + NONCE_LEN..];

    // Derive key
    let key = derive_key(password, salt);

    // Create cipher
    let cipher = Aes256Gcm::new_from_slice(key.expose())
        .map_err(|e| SecretsError::DecryptionFailed(e.to_string()))?;

    let nonce = Nonce::from_slice(nonce_bytes);

    // Decrypt
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| SecretsError::VaultCorrupted)?;

    Ok(plaintext)
}

/// Encrypt data with a raw key (for vault encryption with master key)
pub fn encrypt_with_key(data: &[u8], key: &SecretKey) -> Result<Vec<u8>> {
    // Generate random salt and nonce
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    // Create cipher
    let cipher = Aes256Gcm::new_from_slice(key.expose())
        .map_err(|e| SecretsError::EncryptionFailed(e.to_string()))?;

    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt
    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|e| SecretsError::EncryptionFailed(e.to_string()))?;

    // Combine salt + nonce + ciphertext (salt not used but kept for format compatibility)
    let mut result = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    result.extend_from_slice(&salt);
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt data with a raw key
pub fn decrypt_with_key(encrypted: &[u8], key: &SecretKey) -> Result<Vec<u8>> {
    if encrypted.len() < SALT_LEN + NONCE_LEN + 16 {
        return Err(SecretsError::VaultCorrupted);
    }

    // Extract nonce and ciphertext (skip salt)
    let nonce_bytes = &encrypted[SALT_LEN..SALT_LEN + NONCE_LEN];
    let ciphertext = &encrypted[SALT_LEN + NONCE_LEN..];

    // Create cipher
    let cipher = Aes256Gcm::new_from_slice(key.expose())
        .map_err(|e| SecretsError::DecryptionFailed(e.to_string()))?;

    let nonce = Nonce::from_slice(nonce_bytes);

    // Decrypt
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| SecretsError::VaultCorrupted)?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let data = b"Hello, World!";
        let password = "test-password";

        let encrypted = encrypt(data, password).unwrap();
        assert_ne!(encrypted, data);

        let decrypted = decrypt(&encrypted, password).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_wrong_password() {
        let data = b"Hello, World!";
        let password = "test-password";
        let wrong_password = "wrong-password";

        let encrypted = encrypt(data, password).unwrap();
        let result = decrypt(&encrypted, wrong_password);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_decrypt_with_key() {
        let data = b"Secret data";
        let key = SecretKey::generate();

        let encrypted = encrypt_with_key(data, &key).unwrap();
        let decrypted = decrypt_with_key(&encrypted, &key).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_derive_key_consistency() {
        let password = "my-password";
        let salt = [0u8; 16];

        let key1 = derive_key(password, &salt);
        let key2 = derive_key(password, &salt);

        assert_eq!(key1.expose(), key2.expose());
    }
}
