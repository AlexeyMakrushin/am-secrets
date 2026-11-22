use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::errors::{Result, SecretsError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_version")]
    pub version: u32,

    #[serde(default = "default_provider")]
    pub provider: String,

    #[serde(default)]
    pub whitelist: Vec<String>,

    #[serde(default)]
    pub daemon: DaemonConfig,

    #[serde(default)]
    pub bitwarden: BitwardenConfig,

    #[serde(default)]
    pub onepassword: OnePasswordConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitwardenConfig {
    /// Bitwarden account email (for automatic login)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,

    /// Custom server URL (required, no default)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,


}

impl Default for BitwardenConfig {
    fn default() -> Self {
        Self {
            email: None,
            server: None,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OnePasswordConfig {
    /// 1Password account (e.g., "my.1password.com")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
}

fn default_version() -> u32 {
    2
}

fn default_provider() -> String {
    "bitwarden".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    #[serde(default = "default_socket")]
    pub socket: String,
    #[serde(default = "default_auto_start")]
    pub auto_start: bool,
}

fn default_socket() -> String {
    "~/.secrets/daemon.sock".to_string()
}

fn default_auto_start() -> bool {
    true
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            socket: default_socket(),
            auto_start: default_auto_start(),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: 2,
            provider: "bitwarden".to_string(),
            whitelist: vec![
                "python3".to_string(),
                "node".to_string(),
                "npm".to_string(),
                "bun".to_string(),
                "go".to_string(),
                "cargo".to_string(),
                "ruby".to_string(),
            ],
            daemon: DaemonConfig::default(),
            bitwarden: BitwardenConfig::default(),
            onepassword: OnePasswordConfig::default(),
        }
    }
}

impl Config {
    /// Valid provider names
    const VALID_PROVIDERS: &'static [&'static str] = &["bitwarden", "1password", "keychain"];

    /// Get the secrets directory path
    pub fn secrets_dir() -> PathBuf {
        if let Some(path) = std::env::var_os("SECRETS_HOME") { return PathBuf::from(path); }
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
        home.join(".secrets")
    }

    /// Validate config
    pub fn validate(&self) -> Result<()> {
        if !Self::VALID_PROVIDERS.contains(&self.provider.as_str()) {
            return Err(SecretsError::ConfigInvalid(format!(
                "Invalid provider '{}'. Valid: {}",
                self.provider,
                Self::VALID_PROVIDERS.join(", ")
            )));
        }
        Ok(())
    }

    /// Get the config file path
    pub fn config_path() -> PathBuf {
        Self::secrets_dir().join("config.yaml")
    }

    /// Load config from file
    pub fn load() -> Result<Self> {
        let path = Self::config_path();
        Self::load_from(&path)
    }

    /// Load config from specific path
    pub fn load_from(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Err(SecretsError::ConfigNotFound(
                path.to_string_lossy().to_string(),
            ));
        }

        let content = fs::read_to_string(path).map_err(|e| {
            SecretsError::ConfigInvalid(format!("Could not read config: {}", e))
        })?;

        let config: Config = serde_yaml::from_str(&content).map_err(|e| {
            SecretsError::ConfigInvalid(format!("Invalid YAML: {}", e))
        })?;

        // Validate config
        config.validate()?;

        Ok(config)
    }

    /// Save config to file
    pub fn save(&self) -> Result<()> {
        let path = Self::config_path();
        self.save_to(&path)
    }

    /// Save config to specific path
    pub fn save_to(&self, path: &Path) -> Result<()> {
        // Ensure directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                SecretsError::ConfigInvalid(format!("Could not create directory: {}", e))
            })?;
        }

        let content = serde_yaml::to_string(self)
            .map_err(|e| SecretsError::ConfigInvalid(format!("Could not serialize config: {}", e)))?;

        crate::vault::atomic_write(path, content.as_bytes())
            .map_err(|e| SecretsError::ConfigInvalid(format!("Could not write config: {e}")))
    }

    /// Get the socket path (expanded)
    pub fn socket_path(&self) -> PathBuf {
        let path = &self.daemon.socket;
        if let Some(rest) = path.strip_prefix("~/") {
            let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
            home.join(rest)
        } else {
            PathBuf::from(path)
        }
    }

    /// Get the vault.enc path
    pub fn vault_path() -> PathBuf {
        Self::secrets_dir().join("vault.enc")
    }

    /// Get the keys.json path
    pub fn keys_path() -> PathBuf {
        Self::secrets_dir().join("keys.json")
    }

    /// Get the trusted_hashes path
    pub fn trusted_hashes_path() -> PathBuf {
        Self::secrets_dir().join("trusted_hashes")
    }

    /// Get the logs directory path
    pub fn logs_dir() -> PathBuf {
        Self::secrets_dir().join("logs")
    }

    /// Check if command is in whitelist
    pub fn is_whitelisted(&self, command: &str) -> bool {
        // Extract base command name
        let base = Path::new(command)
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| command.to_string());

        self.whitelist.iter().any(|w| w == &base)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.version, 2);
        assert_eq!(config.provider, "bitwarden");
        assert!(config.whitelist.contains(&"python3".to_string()));
    }

    #[test]
    fn test_whitelist_check() {
        let config = Config::default();
        assert!(config.is_whitelisted("python3"));
        assert!(config.is_whitelisted("/usr/bin/python3"));
        assert!(!config.is_whitelisted("malware"));
    }

    #[test]
    fn test_valid_providers() {
        for provider in ["bitwarden", "1password", "keychain"] {
            let mut config = Config::default();
            config.provider = provider.to_string();
            assert!(config.validate().is_ok());
        }
    }

    #[test]
    fn test_invalid_provider() {
        let mut config = Config::default();
        config.provider = "invalid".to_string();
        assert!(config.validate().is_err());
    }
}
