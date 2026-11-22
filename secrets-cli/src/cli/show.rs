use std::fs::OpenOptions;
use std::io::Write;

use crate::auth::auth_local;
use crate::config::Config;
use crate::errors::{Result, SecretsError};
use crate::vault::{load_vault, KeysFile};

pub fn ls_command(item: Option<&str>, field: Option<&str>) -> Result<()> {
    if let (Some(item), Some(field)) = (item, field) {
        return super::get_command(item, field);
    }
    // Check arguments
    if item.is_none() && field.is_some() {
        return Err(SecretsError::ItemNotFound(
            "item required when field is specified".to_string(),
        ));
    }

    // SECURITY: Block access to __pin (canary consistency)
    if let Some(i) = item {
        if i == "__pin" {
            return handle_canary_alert();
        }
    }

    // Load config and keys
    let config = Config::load()?;
    let keys = KeysFile::load(&Config::keys_path())?;

    // Authenticate (PIN or provider password)
    let auth = auth_local(&config, &keys)?;

    // Load and decrypt vault
    let vault = load_vault(&Config::vault_path(), &auth.master_key)?;

    // Display based on arguments
    match (item, field) {
        (None, None) => {
            // Show all items
            println!("Vault contents:");
            println!();

            let mut items: Vec<_> = vault.items.keys().collect();
            items.sort();

            for name in items {
                // Skip system items
                if name.starts_with("__") {
                    continue;
                }

                if let Some(vault_item) = vault.get_item(name) {
                    println!("  \x1b[1m{}\x1b[0m", name);
                    for field_name in vault_item.fields.keys() {
                        println!("    - {}", field_name);
                    }
                    println!();
                }
            }
        }
        (Some(i), None) => {
            // Show specific item
            let vault_item = vault.get_item(i).ok_or_else(|| {
                SecretsError::ItemNotFound(i.to_string())
            })?;

            println!("Item: \x1b[1m{}\x1b[0m", i);
            println!();

            for (field_name, value) in &vault_item.fields {
                // Mask sensitive values
                let masked = mask_value(value);
                println!("  {}: {}", field_name, masked);
            }
        }
        (Some(i), Some(f)) => {
            // Show specific field
            let vault_item = vault.get_item(i).ok_or_else(|| {
                SecretsError::ItemNotFound(i.to_string())
            })?;

            let value = vault_item.get_field(f).ok_or_else(|| {
                SecretsError::FieldNotFound(f.to_string())
            })?;

            // Show unmasked value for specific field query
            println!("{}", value);
        }
        (None, Some(_)) => {
            // Already handled at start
            unreachable!()
        }
    }

    Ok(())
}

/// Mask sensitive values for display (show first/last chars only)
fn mask_value(_value: &str) -> String {
    "[hidden]".to_string()
}

fn handle_canary_alert() -> Result<()> {
    eprintln!("\n\x1b[31m");
    eprintln!("╔══════════════════════════════════════════════════════════════╗");
    eprintln!("║           ⚠️  SECURITY ALERT: Canary access detected!        ║");
    eprintln!("╠══════════════════════════════════════════════════════════════╣");
    eprintln!("║                                                              ║");
    eprintln!("║  The reserved '__pin' entry was accessed.                    ║");
    eprintln!("║  This may indicate:                                          ║");
    eprintln!("║    • Compromised trusted_hashes file                         ║");
    eprintln!("║    • Malware scanning your vault                             ║");
    eprintln!("║    • Unauthorized access attempt                             ║");
    eprintln!("║                                                              ║");
    eprintln!("║  All operations are BLOCKED.                                 ║");
    eprintln!("║                                                              ║");
    eprintln!("║  To continue, you must:                                      ║");
    eprintln!("║    1. Verify your system is not compromised                  ║");
    eprintln!("║    2. Run 'secrets setup' to reinitialize                    ║");
    eprintln!("║    3. Or provide Bitwarden password to unlock                ║");
    eprintln!("║                                                              ║");
    eprintln!("╚══════════════════════════════════════════════════════════════╝");
    eprintln!("\x1b[0m\n");

    // Log the incident
    log_security_incident("Canary access via ls command");

    Err(SecretsError::CanaryTriggered)
}

fn log_security_incident(message: &str) {
    let logs_dir = Config::logs_dir();
    std::fs::create_dir_all(&logs_dir).ok();

    let log_path = logs_dir.join("security.log");
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
    {
        let timestamp = chrono_timestamp();
        let _ = writeln!(file, "[{}] {}", timestamp, message);
    }
}

fn chrono_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    format!("{}", secs)
}
