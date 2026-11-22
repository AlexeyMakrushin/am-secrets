//! Detached refresh: fetch outside the foreground lock; commit only an unchanged snapshot.
use crate::{
    auth,
    config::Config,
    daemon::DaemonClient,
    errors::{Result, SecretsError},
    providers,
    vault::{load_vault, save_vault, KeysFile},
};
use std::{
    fs::{File, OpenOptions},
    os::unix::{fs::OpenOptionsExt, process::CommandExt},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn status_path() -> std::path::PathBuf {
    Config::secrets_dir().join("local-sync-status.json")
}
fn read_status() -> serde_json::Value {
    std::fs::read(status_path())
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_else(|| serde_json::json!({}))
}
fn record(outcome: &str) {
    record_detail(outcome, None, None);
}
fn record_detail(outcome: &str, reason: Option<&str>, reference: Option<&str>) {
    let mut status = read_status();
    status["last_attempt"] = now().into();
    status["outcome"] = outcome.into();
    status["reason"] = reason.into();
    status["reference"] = reference.into();
    if outcome == "success" {
        status["last_success"] = now().into();
    }
    let _ = crate::vault::atomic_write(&status_path(), status.to_string().as_bytes());
}
pub fn report() {
    let s = read_status();
    if s["outcome"] == "failed" {
        eprintln!(
            "Background refresh failed ({}); local snapshot preserved. Run secrets sync for details.",
            s["reason"].as_str().unwrap_or("unknown")
        );
        if let Some(reference) = s["reference"].as_str() {
            eprintln!("Missing provider reference: {reference:?}");
        }
    }
}
pub fn show_status() {
    let s = read_status();
    println!(
        "Local background refresh: {}; last success (Unix seconds): {}",
        s["outcome"].as_str().unwrap_or("not run"),
        s["last_success"]
    );
}
pub fn invalidate_generation() -> Result<()> {
    crate::vault::atomic_write(
        &Config::secrets_dir().join("session-generation"),
        &rand::random::<[u8; 16]>(),
    )
}
fn generation() -> Vec<u8> {
    std::fs::read(Config::secrets_dir().join("session-generation")).unwrap_or_default()
}
fn client(config: &Config) -> DaemonClient {
    DaemonClient::with_auto_start(config.socket_path().to_string_lossy().into(), false)
}

pub fn schedule() {
    let Ok(config) = Config::load() else { return };
    if config.provider != "bitwarden" {
        return;
    }
    let Ok(keys) = KeysFile::load(&Config::keys_path()) else {
        return;
    };
    let Ok(scope) = auth::context(&config, &keys) else {
        return;
    };
    if client(&config).check_session(&scope).ok() != Some(true) {
        return;
    }
    let s = read_status();
    if s["last_attempt"]
        .as_u64()
        .is_some_and(|last| now().saturating_sub(last) < 60)
    {
        return;
    }
    let Ok(probe) = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(Config::secrets_dir().join(".background.lock"))
    else {
        return;
    };
    if probe.try_lock().is_err() {
        return;
    }
    drop(probe);
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let mut command = Command::new(exe);
    if let Ok(names) = std::env::var("SECRETS_INJECTED") {
        for name in names.split(',').filter(|n| !n.is_empty()) {
            command.env_remove(name);
        }
    }
    let result = command
        .arg("refresh-local")
        .env_remove("BW_SESSION")
        .env_remove("BW_PASSWORD")
        .env_remove("SECRETS_INJECTED")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .current_dir(Config::secrets_dir())
        .process_group(0)
        .spawn();
    if result.is_err() {
        record("failed");
    }
}

pub fn run() -> Result<()> {
    let config = Config::load()?;
    if config.provider != "bitwarden" {
        return Ok(());
    }
    let file: File = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(Config::secrets_dir().join(".background.lock"))?;
    if file.try_lock().is_err() {
        return Ok(());
    }
    let s = read_status();
    if s["last_attempt"]
        .as_u64()
        .is_some_and(|last| now().saturating_sub(last) < 60)
    {
        return Ok(());
    }
    record("running");
    let result = refresh(&config);
    match &result {
        Ok(true) => record("success"),
        Ok(false) => record("superseded; retry after next command"),
        Err(error) => record_detail(
            "failed",
            Some(failure_reason(error)),
            match error {
                SecretsError::ItemNotFound(reference) | SecretsError::FieldNotFound(reference) => {
                    Some(reference)
                }
                _ => None,
            },
        ),
    }
    result.map(|_| ())
}

fn refresh(_config: &Config) -> Result<bool> {
    let lock = crate::command_lock::acquire()?;
    let config = &Config::load()?;
    let keys = KeysFile::load(&Config::keys_path())?;
    let scope = auth::context(config, &keys)?;
    let daemon = client(config);
    let state = daemon.get_state(&scope)?; // cached only; never prompts or starts daemon
    if state.session.is_empty() {
        return Err(SecretsError::BitwardenSessionExpired);
    }
    let epoch = generation();
    let config_bytes = std::fs::read(Config::config_path())?;
    let keys_bytes = std::fs::read(Config::keys_path())?;
    let snapshot = std::fs::read(Config::vault_path())?;
    let mut vault = load_vault(&Config::vault_path(), &state.master_key)?;
    drop(lock);
    crate::preflight::refresh()?;
    if !auth::provider_session_valid(config, &state.session)? {
        return Err(SecretsError::BitwardenSessionExpired);
    }
    let provider = providers::create_provider(&config.provider, Some(state.session.to_string()))?;
    // Fetch exact existing fields; no new fields and no policy mutations.
    for (item, local) in vault
        .items
        .iter_mut()
        .filter(|(name, _)| !name.starts_with("__"))
    {
        let remote = provider
            .get_item(item)?
            .ok_or_else(|| SecretsError::ItemNotFound(item.clone()))?;
        for (field, value) in &mut local.fields {
            let found = remote
                .fields
                .iter()
                .find(|(name, _)| name == field)
                .ok_or_else(|| SecretsError::FieldNotFound(format!("{item}/{field}")))?;
            *value = found.1.clone();
        }
    }
    let _lock = crate::command_lock::acquire()?;
    if epoch != generation()
        || config_bytes != std::fs::read(Config::config_path())?
        || keys_bytes != std::fs::read(Config::keys_path())?
        || snapshot != std::fs::read(Config::vault_path())?
        || daemon.check_session(&scope).ok() != Some(true)
    {
        return Ok(false);
    }
    save_vault(&vault, &Config::vault_path(), &state.master_key)?;
    Ok(true)
}

// Persist only fixed categories: provider stderr can contain credentials.
fn failure_reason(error: &SecretsError) -> &'static str {
    match error {
        SecretsError::BitwardenLoginFailed(message) => {
            if message.contains("timed out") {
                "bitwarden_timeout"
            } else if message.contains("Invalid JSON from bw") {
                "bitwarden_invalid_json"
            } else if message.contains("Duplicate field names") {
                "bitwarden_duplicate_fields"
            } else if message.contains("Multiple records named") {
                "bitwarden_duplicate_items"
            } else {
                "bitwarden_request_failed"
            }
        }
        SecretsError::BitwardenSessionExpired | SecretsError::SessionExpired => "session_expired",
        SecretsError::ItemNotFound(_) => "provider_item_missing",
        SecretsError::FieldNotFound(_) => "provider_field_missing",
        SecretsError::DaemonUnauthorized => "daemon_unauthorized",
        SecretsError::DaemonNotRunning | SecretsError::DaemonConnectionFailed(_) => {
            "daemon_unavailable"
        }
        SecretsError::StorageWriteFailed(_) => "storage_write_failed",
        SecretsError::ConfigInvalid(message) if message.starts_with("Another secrets command") => {
            "command_busy"
        }
        SecretsError::ConfigInvalid(_) | SecretsError::ConfigNotFound(_) => "configuration_invalid",
        SecretsError::VaultNotFound(_) => "vault_missing",
        SecretsError::VaultCorrupted | SecretsError::DecryptionFailed(_) => "vault_unreadable",
        SecretsError::DaemonRateLimited(_) => "daemon_rate_limited",
        SecretsError::InvalidResponse(_) => "daemon_invalid_response",
        SecretsError::BitwardenNotInstalled => "bitwarden_not_installed",
        _ => "refresh_failed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn background_error_categories_never_include_provider_payloads() {
        for (message, expected) in [
            ("bw timed out", "bitwarden_timeout"),
            ("Invalid JSON from bw", "bitwarden_invalid_json"),
            (
                "Duplicate field names in Bitwarden item",
                "bitwarden_duplicate_fields",
            ),
            (
                "Multiple records named 'sensitive-name'",
                "bitwarden_duplicate_items",
            ),
            ("synthetic-secret-value", "bitwarden_request_failed"),
        ] {
            assert_eq!(
                failure_reason(&SecretsError::BitwardenLoginFailed(message.into())),
                expected
            );
        }
        assert_eq!(
            failure_reason(&SecretsError::FieldNotFound("private/field".into())),
            "provider_field_missing"
        );
    }
}
