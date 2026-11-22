//! Local key and provider session live in the verified daemon, never in files.
use crate::config::Config;
use crate::daemon::DaemonClient;
use crate::errors::{Result, SecretsError};
use crate::security::SecretKey;
use crate::vault::{load_vault, KeysFile};
use sha2::{Digest, Sha256};
use std::io::{self, IsTerminal, Write};
use zeroize::Zeroizing;

pub fn is_interactive() -> bool {
    std::io::stdin().is_terminal()
}
pub struct AuthResult {
    pub master_key: SecretKey,
}

pub fn daemon(config: &Config) -> DaemonClient {
    DaemonClient::with_auto_start(
        config.socket_path().to_string_lossy().into(),
        config.daemon.auto_start,
    )
}

pub fn context(config: &Config, keys: &KeysFile) -> Result<String> {
    let identity = serde_json::to_vec(&serde_json::json!({
        "keys": std::fs::canonicalize(Config::keys_path())?,
        "wrap": keys.wrap_bw,
        "provider": config.provider,
        "server": config.bitwarden.server,
        "email": config.bitwarden.email,
        "account": config.onepassword.account,
    }))
    .map_err(|_| SecretsError::VaultCorrupted)?;
    Ok(format!("{:x}", Sha256::digest(identity)))
}

fn prompt_password() -> Result<Zeroizing<String>> {
    if !is_interactive() {
        return Err(SecretsError::ConfigInvalid("Vault locked. Run 'secrets unlock' in your terminal; never send the password to an agent.".into()));
    }
    eprint!("Master password: ");
    io::stderr().flush()?;
    let password = Zeroizing::new(rpassword::read_password()?);
    if password.is_empty() {
        return Err(SecretsError::ConfigInvalid(
            "Password cannot be empty".into(),
        ));
    }
    Ok(password)
}

fn authenticate(
    config: &Config,
    keys: &KeysFile,
    require_provider: bool,
    force_password: bool,
) -> Result<(AuthResult, Zeroizing<String>)> {
    let require_provider = require_provider && provider_requires_session(&config.provider);
    let client = daemon(config);
    let scope = context(config, keys)?;
    if !force_password {
        match client.get_state(&scope) {
            Ok(state) => {
                if !require_provider
                    || (!state.session.is_empty()
                        && provider_session_valid(config, &state.session)?)
                {
                    return Ok((
                        AuthResult {
                            master_key: state.master_key,
                        },
                        state.session,
                    ));
                }
            }
            Err(SecretsError::SessionExpired) => {}
            Err(error) => return Err(error),
        }
    }
    let password = prompt_password()?;
    let key = keys.decrypt_master_key(&password)?;
    // Check the real vault BEFORE retiring the old wrap or caching a key.
    load_vault(&Config::vault_path(), &key)?;
    let session = match unlock_provider(&password, config) {
        Ok(session) => Zeroizing::new(session),
        Err(error) if !require_provider => {
            eprintln!("Error: provider unlock failed: {error}. Local vault remains available.");
            Zeroizing::new(String::new())
        }
        Err(error) => return Err(error),
    };
    drop(password);
    if keys.has_pin_wrap() {
        client.retire_legacy_pin()?;
    }
    keys.retire_pin(&Config::keys_path())?;
    // Cleanup is migration-only and never reads old credentials.
    for path in [
        Config::secrets_dir().join(".bw_session"),
        dirs::home_dir().unwrap_or_default().join(".bw_session"),
    ] {
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
    }
    crate::background::invalidate_generation()?;
    client.set_state(&scope, &key, &session)?;
    Ok((AuthResult { master_key: key }, session))
}

pub fn auth_local(config: &Config, keys: &KeysFile) -> Result<AuthResult> {
    authenticate(config, keys, false, false).map(|(auth, _)| auth)
}

pub fn auth_provider_cached(
    config: &Config,
    keys: &KeysFile,
) -> Result<(AuthResult, Zeroizing<String>)> {
    authenticate(config, keys, true, false)
}

pub fn unlock_command() -> Result<()> {
    let config = Config::load()?;
    let keys = KeysFile::load(&Config::keys_path())?;
    let _ = authenticate(&config, &keys, true, false)?;
    println!("Unlocked until daemon stops or secrets lock.");
    Ok(())
}

pub fn lock_command() -> Result<()> {
    let config = Config::load()?;
    crate::background::invalidate_generation()?;
    daemon(&config).clear_state()?;
    println!("Local key and provider session cleared from daemon memory.");
    Ok(())
}

pub(crate) fn provider_session_valid(config: &Config, session: &str) -> Result<bool> {
    if config.provider != "bitwarden" {
        return Ok(true);
    }
    let output = crate::preflight::output(
        std::process::Command::new("bw")
            .arg("status")
            .env("BW_SESSION", session)
            .env_remove("BW_PASSWORD"),
        std::time::Duration::from_secs(20),
    )?;
    if !output.status.success() {
        return Err(SecretsError::BitwardenLoginFailed(
            "Unable to check provider session".into(),
        ));
    }
    let status: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| SecretsError::BitwardenLoginFailed("Invalid bw status".into()))?;
    if status["status"] != "unlocked" {
        return Ok(false);
    }
    validate_identity(config, &status)?;
    Ok(true)
}

fn validate_identity(config: &Config, status: &serde_json::Value) -> Result<()> {
    let email = config.bitwarden.email.as_deref().unwrap_or("");
    let server = config.bitwarden.server.as_deref().unwrap_or("");
    if status["userEmail"].as_str() != Some(email) {
        return Err(SecretsError::BitwardenLoginFailed("Bitwarden account/server does not match config. Configure the intended account in your terminal.".into()));
    }
    let active_server = status["serverUrl"].as_str().filter(|url| !url.trim().is_empty())
        .ok_or_else(|| SecretsError::BitwardenLoginFailed(
            "bw status did not report a server URL. Use a Bitwarden CLI profile configured with the explicit vault URL, then retry.".into()
        ))?;
    if normalize_server_url(active_server) != normalize_server_url(server) {
        return Err(SecretsError::BitwardenLoginFailed("Bitwarden account/server does not match config. Configure the intended account in your terminal.".into()));
    }
    Ok(())
}

/// Unlock provider and get session token
/// Handles both login (if not logged in) and unlock (if locked)
pub fn unlock_provider(password: &str, config: &Config) -> Result<String> {
    match config.provider.as_str() {
        "bitwarden" => unlock_bitwarden(password, config),
        "1password" => unlock_1password(password),
        "keychain" => Ok(String::new()), // macOS handles auth
        provider => Err(SecretsError::ConfigInvalid(format!(
            "Unknown provider: {}",
            provider
        ))),
    }
}

/// Verify bw belongs to the configured identity. Never log out another account.
fn unlock_bitwarden(password: &str, config: &Config) -> Result<String> {
    use std::process::Command;
    let mut command = Command::new("bw");
    command
        .arg("status")
        .env_remove("BW_SESSION")
        .env_remove("BW_PASSWORD");
    let output = crate::preflight::output(&mut command, std::time::Duration::from_secs(20))?;
    if !output.status.success() {
        return Err(SecretsError::BitwardenLoginFailed(
            "bw status failed".into(),
        ));
    }
    let status: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| SecretsError::BitwardenLoginFailed("Invalid bw status".into()))?;
    let mut unlock = Command::new("bw");
    let needs_login = status["status"] == "unauthenticated";
    if needs_login {
        let server = config
            .bitwarden
            .server
            .as_deref()
            .ok_or_else(|| SecretsError::ConfigInvalid("Bitwarden server missing".into()))?;
        let email = config
            .bitwarden
            .email
            .as_deref()
            .ok_or_else(|| SecretsError::ConfigInvalid("Bitwarden email missing".into()))?;
        if status["serverUrl"].as_str().map(normalize_server_url)
            != Some(normalize_server_url(server))
        {
            let server = if normalize_server_url(server) == "https://vault.bitwarden.com" {
                "https://vault.bitwarden.com"
            } else {
                server
            };
            let configured = crate::preflight::output(
                Command::new("bw")
                    .args(["config", "server", server])
                    .env_remove("BW_SESSION")
                    .env_remove("BW_PASSWORD"),
                std::time::Duration::from_secs(20),
            )?;
            if !configured.status.success() {
                return Err(SecretsError::BitwardenLoginFailed(
                    "bw config server failed".into(),
                ));
            }
        }
        unlock.args(["login", email]);
    } else {
        validate_identity(config, &status)?;
        unlock.arg("unlock");
    }
    unlock
        .args(["--raw", "--passwordenv", "BW_PASSWORD"])
        .env("BW_PASSWORD", password)
        .env_remove("BW_SESSION");
    let mut output = crate::preflight::output(&mut unlock, std::time::Duration::from_secs(30))
        .map_err(|error| SecretsError::BitwardenLoginFailed(format!("bw failed: {error}. If login needs verification, run bw login in your terminal and retry.")))?;
    // The command owns an environment copy; drop it as soon as bw exits.
    drop(unlock);
    use zeroize::Zeroize;
    output.stderr.zeroize();
    if !output.status.success() {
        output.stdout.zeroize();
        return Err(SecretsError::BitwardenLoginFailed(if needs_login {
            "bw login failed. For two-step login or a new-device check, run bw login in your terminal and retry.".into()
        } else {
            "bw unlock failed. Check the master password and retry.".into()
        }));
    }
    let session = String::from_utf8_lossy(&output.stdout).trim().to_string();
    output.stdout.zeroize();
    if session.is_empty() {
        return Err(SecretsError::BitwardenLoginFailed(
            "Empty session; check login and 2FA in your terminal".into(),
        ));
    }
    Ok(session)
}

/// Normalize server URL for comparison
fn normalize_server_url(url: &str) -> String {
    let url = url.trim().to_lowercase();
    let url = if url.starts_with("http://") || url.starts_with("https://") {
        url
    } else {
        format!("https://{}", url)
    };
    match url.trim_end_matches('/') {
        "https://bitwarden.com" => "https://vault.bitwarden.com".into(),
        normalized => normalized.to_string(),
    }
}

/// 1Password unlock flow
fn unlock_1password(password: &str) -> Result<String> {
    use std::process::Command;

    let output = Command::new("op")
        .args(["signin", "--raw"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            if let Some(stdin) = child.stdin.as_mut() {
                stdin.write_all(password.as_bytes())?;
                stdin.write_all(b"\n")?;
            }
            child.wait_with_output()
        })
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                SecretsError::ConfigInvalid(
                    "1Password CLI not installed. Install: brew install 1password-cli".to_string(),
                )
            } else {
                SecretsError::ConfigInvalid(format!("Failed to run op: {}", e))
            }
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SecretsError::ConfigInvalid(format!(
            "1Password signin failed: {}",
            stderr.trim()
        )));
    }

    let session = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(session)
}

/// Check if provider requires a session/password for operations
pub fn provider_requires_session(provider: &str) -> bool {
    match provider {
        "keychain" => false,
        _ => true,
    }
}

/// Get password prompt text for provider
pub fn provider_password_prompt(provider: &str) -> &'static str {
    match provider {
        "bitwarden" => "Bitwarden master password",
        "1password" => "1Password master password",
        "keychain" => "Recovery password",
        _ => "Provider password",
    }
}

/// Permission changes always require a new human-entered password.
pub fn confirm(config: &Config, keys: &KeysFile) -> Result<(AuthResult, Zeroizing<String>)> {
    authenticate(config, keys, false, true)
}
