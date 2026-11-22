use std::fs;
use std::path::Path;

use crate::errors::{Result, SecretsError};
use crate::security::SecretKey;
use crate::vault::crypto::{decrypt_with_key, encrypt_with_key};
use crate::vault::types::Vault;

/// Load and decrypt vault from file
pub fn load_vault(path: &Path, master_key: &SecretKey) -> Result<Vault> {
    if !path.exists() {
        return Err(SecretsError::VaultNotFound(
            path.to_string_lossy().to_string(),
        ));
    }

    let encrypted = fs::read(path).map_err(|_| SecretsError::VaultCorrupted)?;

    let decrypted = zeroize::Zeroizing::new(decrypt_with_key(&encrypted, master_key)?);

    let vault: Vault = serde_json::from_slice(&decrypted).map_err(|e| {
        SecretsError::DecryptionFailed(format!("Invalid vault JSON: {}", e))
    })?;

    Ok(vault)
}

/// Encrypt and save vault to file (atomic: temp + rename)
/// Resolves symlinks so that the actual target file is updated in-place,
/// preserving the symlink. An unreachable target returns an error.
pub fn save_vault(vault: &Vault, path: &Path, master_key: &SecretKey) -> Result<()> {
    // Serialize vault to JSON
    let json = zeroize::Zeroizing::new(serde_json::to_vec_pretty(vault)
        .map_err(|e| SecretsError::EncryptionFailed(e.to_string()))?);

    // Encrypt
    let encrypted = encrypt_with_key(&json, master_key)?;

    atomic_write(path, &encrypted)
}

/// Never replace a dangling symlink; use unique, private temp files beside target.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let resolved = if fs::symlink_metadata(path).is_ok() {
        fs::canonicalize(path).map_err(|_| SecretsError::VaultCorrupted)?
    } else { path.to_path_buf() };
    let parent = resolved.parent().ok_or(SecretsError::VaultCorrupted)?;
    fs::create_dir_all(parent).map_err(|e| SecretsError::StorageWriteFailed(e.to_string()))?;
    let temp = parent.join(format!(".secrets-{}-{}.tmp", std::process::id(), rand::random::<u64>()));
    let result = (|| -> std::io::Result<()> {
        let mut file = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temp, &resolved)?;
        Ok(())
    })();
    if result.is_err() { let _ = fs::remove_file(&temp); }
    result.map_err(|e| SecretsError::StorageWriteFailed(format!("{}: {e}", path.display())))
}

/// Check if vault exists
#[allow(dead_code)] // Reserved for status command
pub fn vault_exists(path: &Path) -> bool {
    path.exists()
}

/// Create backup of vault
#[allow(dead_code)] // Reserved for backup command
pub fn backup_vault(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    let backup_dir = path.parent().unwrap().join("backup");
    fs::create_dir_all(&backup_dir).map_err(|e| {
        SecretsError::EncryptionFailed(format!("Could not create backup directory: {}", e))
    })?;

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let backup_name = format!(
        "{}.{}.bak",
        path.file_name().unwrap().to_string_lossy(),
        timestamp
    );

    let backup_path = backup_dir.join(backup_name);

    fs::copy(path, &backup_path).map_err(|e| {
        SecretsError::EncryptionFailed(format!("Could not create backup: {}", e))
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Свой временный каталог вместо зависимости tempfile:
    /// тесты должны собираться без сети.
    fn scratch_dir() -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir()
            .join(format!("ai-secrets-test-{}-{}", std::process::id(), nanos));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_vault_roundtrip() {
        let dir = scratch_dir();
        let path = dir.join("vault.enc");
        let master_key = SecretKey::generate();

        let mut vault = Vault::new_with_canary();
        vault.items.insert(
            "test".to_string(),
            crate::vault::types::VaultItem {
                fields: {
                    let mut fields = std::collections::HashMap::new();
                    fields.insert("api-key".to_string(), "secret123".to_string());
                    fields
                },
                dirs: vec!["/test".to_string()],
                meta: None,
            },
        );

        save_vault(&vault, &path, &master_key).unwrap();
        let loaded = load_vault(&path, &master_key).unwrap();

        assert_eq!(loaded.items.len(), vault.items.len());
        assert!(loaded.items.contains_key("test"));
        assert!(loaded.items.contains_key("__pin"));
    }
}
