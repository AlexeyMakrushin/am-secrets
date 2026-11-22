#[cfg(test)]
use crate::vault::crypto::{decrypt_with_key, encrypt_with_key};
use std::fs;
use std::path::Path;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};

use crate::errors::{Result, SecretsError};
use crate::security::SecretKey;
use crate::vault::crypto::{decrypt, encrypt};

/// Ключ разблокировки взят напрямую, без растягивания пароля.
///
/// Обычный режим (поле отсутствует или равно "pbkdf2") считает ключ как
/// PBKDF2-SHA256(pin) — это нужно, когда pin придумал человек и у него мало
/// энтропии. Если pin сгенерирован случайным (32 байта), растягивать нечего:
/// энтропии уже достаточно, а 600 000 итераций стоят около трети секунды
/// на каждом вызове.
#[cfg(test)]
pub const PIN_KDF_RAW: &str = "raw";

/// Сгенерировать ключ разблокировки: 32 случайных байта в base64.
///
/// Возвращает (строка для Keychain, ключ). Строку кладём в Keychain через
/// демона — протокол не меняется, он по-прежнему про «PIN».
#[cfg(test)]
pub fn generate_unlock_secret() -> (String, SecretKey) {
    let key = SecretKey::generate();
    (BASE64.encode(key.expose()), key)
}

/// Разобрать ключ разблокировки из строки, которую отдал демон.
#[cfg(test)]
pub fn unlock_key_from_b64(value: &str) -> Result<SecretKey> {
    let raw = BASE64.decode(value.trim()).map_err(|_| {
        SecretsError::DecryptionFailed(
            "Unlock secret is not valid base64. Re-run 'secrets pin' to regenerate it.".to_string(),
        )
    })?;
    SecretKey::from_slice(&raw).ok_or_else(|| {
        SecretsError::DecryptionFailed(
            "Unlock secret must be 32 bytes. Re-run 'secrets pin' to regenerate it.".to_string(),
        )
    })
}

/// Keys file structure (v2)
///
/// Contains master_key encrypted with two different passwords:
/// - wrap_pin: encrypted with user's PIN (for daily use)
/// - wrap_bw: encrypted with Bitwarden password (for recovery)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeysFile {
    pub version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wrap_pin: Option<EncryptedBlob>,
    pub wrap_bw: EncryptedBlob,
    /// Как выведен ключ из wrap_pin. Отсутствует или "pbkdf2" — растягивание
    /// пароля (старые файлы и человеческий PIN). "raw" — pin это base64 от
    /// 32 случайных байт, ключ берётся напрямую. См. PIN_KDF_RAW.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin_kdf: Option<String>,
}

/// Encrypted blob with base64-encoded components
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedBlob {
    pub salt: String,   // base64
    pub nonce: String,  // base64
    pub ciphertext: String, // base64
}

impl EncryptedBlob {
    /// Create from raw encrypted bytes (salt + nonce + ciphertext)
    pub fn from_bytes(encrypted: &[u8]) -> Result<Self> {
        if encrypted.len() < 16 + 12 + 16 {
            return Err(SecretsError::VaultCorrupted);
        }

        let salt = BASE64.encode(&encrypted[..16]);
        let nonce = BASE64.encode(&encrypted[16..28]);
        let ciphertext = BASE64.encode(&encrypted[28..]);

        Ok(Self {
            salt,
            nonce,
            ciphertext,
        })
    }

    /// Convert to raw bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let salt = BASE64.decode(&self.salt)
            .map_err(|_| SecretsError::VaultCorrupted)?;
        let nonce = BASE64.decode(&self.nonce)
            .map_err(|_| SecretsError::VaultCorrupted)?;
        let ciphertext = BASE64.decode(&self.ciphertext)
            .map_err(|_| SecretsError::VaultCorrupted)?;

        let mut result = Vec::with_capacity(salt.len() + nonce.len() + ciphertext.len());
        result.extend_from_slice(&salt);
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }
}

impl KeysFile {
    /// Create new keys file with master key wrapped by both PIN and BW password
    #[cfg(test)]
    pub fn new(master_key: &SecretKey, pin: &str, bw_password: &str) -> Result<Self> {
        let encrypted_pin = encrypt(master_key.expose(), pin)?;
        let wrap_pin = EncryptedBlob::from_bytes(&encrypted_pin)?;

        let encrypted_bw = encrypt(master_key.expose(), bw_password)?;
        let wrap_bw = EncryptedBlob::from_bytes(&encrypted_bw)?;

        Ok(Self {
            version: 2,
            wrap_pin: Some(wrap_pin),
            wrap_bw,
            pin_kdf: None,
        })
    }

    /// Create new keys file with only BW wrap (for migration or recovery)
    #[allow(dead_code)] // Reserved for migrate command
    pub fn new_bw_only(master_key: &SecretKey, bw_password: &str) -> Result<Self> {
        let encrypted = encrypt(master_key.expose(), bw_password)?;
        let wrap_bw = EncryptedBlob::from_bytes(&encrypted)?;

        Ok(Self {
            version: 2,
            wrap_pin: None,
            wrap_bw,
            pin_kdf: None,
        })
    }

    /// Load keys file from path
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Err(SecretsError::VaultNotFound(
                path.to_string_lossy().to_string(),
            ));
        }

        let content = fs::read_to_string(path).map_err(|_| {
            SecretsError::VaultCorrupted
        })?;

        let keys: KeysFile = serde_json::from_str(&content).map_err(|_| {
            SecretsError::VaultCorrupted
        })?;

        if keys.version != 2 {
            return Err(SecretsError::VaultCorrupted);
        }

        Ok(keys)
    }

    /// Save keys file to path (atomic: temp + rename)
    /// Resolves symlinks so the real target is updated, preserving the symlink.
    /// Falls back to original path if symlink target is unreachable.
    pub fn save(&self, path: &Path) -> Result<()> {
        let content = serde_json::to_vec_pretty(self).map_err(|_| SecretsError::VaultCorrupted)?;
        super::storage::atomic_write(path, &content)
    }

    /// Called only after password and vault verification. Preserve the recovery wrap.
    pub fn retire_pin(&self, path: &Path) -> Result<()> {
        if !self.has_pin_wrap() && self.pin_kdf.is_none() { return Ok(()); }
        let mut migrated = self.clone();
        migrated.wrap_pin = None;
        migrated.pin_kdf = None;
        migrated.save(path)
    }

    /// Decrypt master key using PIN (primary daily-use method)
    #[cfg(test)]
    pub fn decrypt_master_key_with_pin(&self, pin: &str) -> Result<SecretKey> {
        let wrap_pin = self.wrap_pin.as_ref()
            .ok_or_else(|| SecretsError::DecryptionFailed(
                "No PIN wrap in keys.json. Run 'secrets setup' to add PIN.".to_string()
            ))?;

        let encrypted = wrap_pin.to_bytes()?;

        let decrypted = if self.uses_raw_unlock() {
            let key = unlock_key_from_b64(pin)?;
            decrypt_with_key(&encrypted, &key)?
        } else {
            decrypt(&encrypted, pin)?
        };

        SecretKey::from_slice(&decrypted).ok_or(SecretsError::VaultCorrupted)
    }

    /// Ключ разблокировки взят напрямую (без PBKDF2)?
    #[cfg(test)]
    pub fn uses_raw_unlock(&self) -> bool {
        self.pin_kdf.as_deref() == Some(PIN_KDF_RAW)
    }

    /// Decrypt master key using Bitwarden password (recovery method)
    pub fn decrypt_master_key(&self, bw_password: &str) -> Result<SecretKey> {
        let encrypted = self.wrap_bw.to_bytes()?;
        let decrypted = zeroize::Zeroizing::new(decrypt(&encrypted, bw_password)?);

        SecretKey::from_slice(&decrypted).ok_or(SecretsError::VaultCorrupted)
    }

    /// Check if PIN wrap is available
    pub fn has_pin_wrap(&self) -> bool {
        self.wrap_pin.is_some()
    }

    /// Add or update PIN wrap
    #[cfg(test)]
    pub fn add_pin_wrap(&mut self, master_key: &SecretKey, pin: &str) -> Result<()> {
        let encrypted = encrypt(master_key.expose(), pin)?;
        self.wrap_pin = Some(EncryptedBlob::from_bytes(&encrypted)?);
        self.pin_kdf = None; // растягивание пароля
        Ok(())
    }

    /// Обернуть мастер-ключ случайным ключом разблокировки (без PBKDF2).
    ///
    /// Строка, которую отдаёт демон, — base64 от 32 случайных байт. Она кладётся
    /// в Keychain под ACL демона, поэтому её не нужно растягивать: перебирать
    /// нечего. Побочный эффект — с каждого вызова снимается ~0.33 с.
    #[cfg(test)]
    pub fn add_pin_wrap_raw(&mut self, master_key: &SecretKey, unlock_b64: &str) -> Result<()> {
        let key = unlock_key_from_b64(unlock_b64)?;
        let encrypted = encrypt_with_key(master_key.expose(), &key)?;
        self.wrap_pin = Some(EncryptedBlob::from_bytes(&encrypted)?);
        self.pin_kdf = Some(PIN_KDF_RAW.to_string());
        Ok(())
    }

    /// Re-encrypt master key with new Bitwarden password
    #[allow(dead_code)] // Reserved for change-bw-password command
    pub fn update_bw_password(&mut self, master_key: &SecretKey, new_bw_password: &str) -> Result<()> {
        let encrypted = encrypt(master_key.expose(), new_bw_password)?;
        self.wrap_bw = EncryptedBlob::from_bytes(&encrypted)?;
        Ok(())
    }

    /// Re-encrypt master key with new PIN
    #[allow(dead_code)] // Reserved for change-pin command
    #[cfg(test)]
    pub fn update_pin(&mut self, master_key: &SecretKey, new_pin: &str) -> Result<()> {
        let encrypted = encrypt(master_key.expose(), new_pin)?;
        self.wrap_pin = Some(EncryptedBlob::from_bytes(&encrypted)?);
        Ok(())
    }
}

/// Check if a file looks like old v1 binary keys format
#[allow(dead_code)] // Reserved for migrate command
pub fn is_v1_keys_file(path: &Path) -> bool {
    if !path.exists() {
        return false;
    }

    // v1 keys file is binary with specific structure:
    // - First 76 bytes: PIN-encrypted master key (salt + nonce + ciphertext)
    // - Next 76 bytes: BW-encrypted master key
    // - Optional: local PIN storage
    if let Ok(data) = fs::read(path) {
        // v1 file should be >= 152 bytes (2 * 76)
        // and should NOT start with '{' (JSON)
        return data.len() >= 152 && data.first() != Some(&b'{');
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keys_file_roundtrip_pin() {
        let master_key = SecretKey::generate();
        let pin = "1234";
        let bw_password = "test-password";

        let keys = KeysFile::new(&master_key, pin, bw_password).unwrap();

        // Decrypt with PIN
        let decrypted_pin = keys.decrypt_master_key_with_pin(pin).unwrap();
        assert_eq!(master_key.expose(), decrypted_pin.expose());

        // Decrypt with BW password
        let decrypted_bw = keys.decrypt_master_key(bw_password).unwrap();
        assert_eq!(master_key.expose(), decrypted_bw.expose());
    }

    #[test]
    fn test_wrong_pin() {
        let master_key = SecretKey::generate();
        let keys = KeysFile::new(&master_key, "1234", "bw-pass").unwrap();

        let result = keys.decrypt_master_key_with_pin("wrong");
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_bw_password() {
        let master_key = SecretKey::generate();
        let keys = KeysFile::new(&master_key, "1234", "correct").unwrap();

        let result = keys.decrypt_master_key("wrong");
        assert!(result.is_err());
    }

    #[test]
    fn test_raw_unlock_roundtrip() {
        let master_key = SecretKey::generate();
        let (secret, _key) = generate_unlock_secret();

        let mut keys = KeysFile::new_bw_only(&master_key, "bw-pass").unwrap();
        keys.add_pin_wrap_raw(&master_key, &secret).unwrap();

        assert!(keys.uses_raw_unlock());
        assert_eq!(keys.pin_kdf.as_deref(), Some(PIN_KDF_RAW));

        let decrypted = keys.decrypt_master_key_with_pin(&secret).unwrap();
        assert_eq!(master_key.expose(), decrypted.expose());
    }

    #[test]
    fn test_raw_unlock_rejects_wrong_secret() {
        let master_key = SecretKey::generate();
        let (secret, _key) = generate_unlock_secret();
        let (other, _key2) = generate_unlock_secret();

        let mut keys = KeysFile::new_bw_only(&master_key, "bw-pass").unwrap();
        keys.add_pin_wrap_raw(&master_key, &secret).unwrap();

        assert!(keys.decrypt_master_key_with_pin(&other).is_err());
        // Мусор вместо base64 тоже должен давать ошибку, а не панику.
        assert!(keys.decrypt_master_key_with_pin("not-base64!!").is_err());
    }

    #[test]
    fn test_legacy_pin_wrap_still_works() {
        // Файл, созданный до перехода на случайный ключ, обязан открываться.
        let master_key = SecretKey::generate();
        let keys = KeysFile::new(&master_key, "1234", "bw-pass").unwrap();

        assert!(!keys.uses_raw_unlock());
        let decrypted = keys.decrypt_master_key_with_pin("1234").unwrap();
        assert_eq!(master_key.expose(), decrypted.expose());
    }

    #[test]
    fn test_add_pin_wrap() {
        let master_key = SecretKey::generate();
        let mut keys = KeysFile::new_bw_only(&master_key, "bw-pass").unwrap();

        assert!(!keys.has_pin_wrap());

        keys.add_pin_wrap(&master_key, "5678").unwrap();

        assert!(keys.has_pin_wrap());
        let decrypted = keys.decrypt_master_key_with_pin("5678").unwrap();
        assert_eq!(master_key.expose(), decrypted.expose());
    }
}

#[cfg(test)]
mod migration_tests {
    use super::*;
    use crate::vault::{Vault, VaultItem, load_vault, save_vault};
    #[test]
    fn old_pin_vault_survives_retirement_and_wrong_password_leaves_it_untouched() {
        let dir = std::env::temp_dir().join(format!("secrets-migration-{}", rand::random::<u64>()));
        fs::create_dir(&dir).unwrap();
        let key = SecretKey::generate();
        let keys = KeysFile::new(&key, "1234", "fixture-master-password").unwrap();
        let keys_path = dir.join("keys.json");
        let vault_path = dir.join("vault.enc");
        keys.save(&keys_path).unwrap();
        let mut vault = Vault::new_with_canary();
        vault.items.insert("test-app".into(), VaultItem { fields: [("token".into(), "fixture-token".into())].into(), dirs: vec!["*".into()], meta: None });
        save_vault(&vault, &vault_path, &key).unwrap();
        let original = fs::read(&keys_path).unwrap();
        let ciphertext = fs::read(&vault_path).unwrap();
        assert!(keys.decrypt_master_key("wrong-password").is_err());
        assert_eq!(fs::read(&keys_path).unwrap(), original);
        // Optional synthetic fixture for the public CLI migration test.
        if let Some(output) = std::env::var_os("SECRETS_TEST_FIXTURE") {
            let output = std::path::PathBuf::from(output);
            fs::create_dir_all(&output).unwrap();
            fs::write(output.join("keys.json"), &original).unwrap();
            // Actual pre-3.2 files do not have an access policy at all.
            let mut legacy = serde_json::to_value(&vault).unwrap();
            legacy.as_object_mut().unwrap().remove("access");
            let bytes = crate::vault::crypto::encrypt_with_key(&serde_json::to_vec(&legacy).unwrap(), &key).unwrap();
            fs::write(output.join("vault.enc"), bytes).unwrap();
        }
        let unlocked = keys.decrypt_master_key("fixture-master-password").unwrap();
        assert!(load_vault(&vault_path, &unlocked).is_ok());
        keys.retire_pin(&keys_path).unwrap();
        let migrated = KeysFile::load(&keys_path).unwrap();
        assert!(!migrated.has_pin_wrap());
        let restored = migrated.decrypt_master_key("fixture-master-password").unwrap();
        let loaded = load_vault(&vault_path, &restored).unwrap();
        assert_eq!(loaded.items["test-app"].fields["token"], "fixture-token");
        assert_eq!(fs::read(&vault_path).unwrap(), ciphertext);
        fs::remove_dir_all(dir).unwrap();
    }
}
