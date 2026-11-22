use crate::auth::auth_local;
use crate::config::Config;
use crate::errors::{Result, SecretsError};
use crate::vault::{load_vault, save_vault, KeysFile, Vault};

pub fn delete_command(item: &str, field: Option<&str>) -> Result<()> {
    // Check for reserved names
    if Vault::is_reserved_name(item) {
        return Err(SecretsError::ReservedName(item.to_string()));
    }

    // Load config and keys
    let config = Config::load()?;
    let keys = KeysFile::load(&Config::keys_path())?;

    // Authenticate (PIN or provider password)
    let auth = auth_local(&config, &keys)?;

    // Load vault
    let mut vault = load_vault(&Config::vault_path(), &auth.master_key)?;

    crate::access::remove(&mut vault, item, field);
    match field {
        None => {
            // Delete entire item
            if vault.items.remove(item).is_some() {
                save_vault(&vault, &Config::vault_path(), &auth.master_key)?;
                println!("\x1b[32mDeleted\x1b[0m item: {}", item);
            } else {
                return Err(SecretsError::ItemNotFound(item.to_string()));
            }
        }
        Some(f) => {
            // Delete field from item
            let vault_item = vault.items.get_mut(item)
                .ok_or_else(|| SecretsError::ItemNotFound(item.to_string()))?;

            if vault_item.fields.remove(f).is_some() {
                save_vault(&vault, &Config::vault_path(), &auth.master_key)?;
                println!("\x1b[32mDeleted\x1b[0m field '{}' from item '{}'", f, item);
            } else {
                return Err(SecretsError::FieldNotFound(f.to_string()));
            }
        }
    }

    Ok(())
}
