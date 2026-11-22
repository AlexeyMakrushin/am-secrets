use std::fs::OpenOptions;
use std::io::{IsTerminal, Write};

use crate::auth::auth_local;
use crate::config::Config;
use crate::errors::{Result, SecretsError};
use crate::vault::{load_vault, KeysFile, Vault};

pub fn get_command(item: &str, field: &str) -> Result<()> {
    // SECURITY: TTY guard — block non-interactive access (LLM protection)
    if !std::io::stdin().is_terminal() {
        return Err(SecretsError::ConfigInvalid(
            "secrets get requires interactive terminal (TTY). Use 'secrets wrap' for scripts.".into()
        ));
    }

    // SECURITY: Check for canary access
    if item == "__pin" {
        return handle_canary_alert();
    }

    // Check for reserved names
    if Vault::is_reserved_name(item) {
        return Err(SecretsError::ReservedName(item.to_string()));
    }

    // Load config
    let config = Config::load()?;

    // Load keys file
    let keys = KeysFile::load(&Config::keys_path())?;

    // Authenticate (PIN or provider password)
    let auth = auth_local(&config, &keys)?;

    // Load and decrypt vault
    let vault = load_vault(&Config::vault_path(), &auth.master_key)?;

    // Get item
    let vault_item = vault.get_item(item)
        .ok_or_else(|| SecretsError::ItemNotFound(item.to_string()))?;

    // Get field
    let value = vault_item.get_field(field)
        .ok_or_else(|| SecretsError::FieldNotFound(field.to_string()))?;

    // Output value (no newline for shell compatibility)
    print!("{}", value);

    Ok(())
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
    eprintln!("║    3. Or provide provider password to unlock                 ║");
    eprintln!("║                                                              ║");
    eprintln!("╚══════════════════════════════════════════════════════════════╝");
    eprintln!("\x1b[0m\n");

    // Log the incident
    log_security_incident("Canary access detected");

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
