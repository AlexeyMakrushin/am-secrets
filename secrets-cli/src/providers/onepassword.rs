//! 1Password provider (op CLI)
//!
//! Uses the `op` CLI to fetch secrets from 1Password.
//! Requires: brew install 1password-cli

use std::process::Command;

use serde::Deserialize;

use crate::errors::{Result, SecretsError};
use crate::providers::{ProviderItem, SecretProvider};

pub struct OnePasswordProvider {
    session: Option<String>,
}

impl OnePasswordProvider {
    pub fn new() -> Self {
        Self { session: None }
    }

    pub fn with_session(session: String) -> Self {
        Self {
            session: if session.is_empty() {
                None
            } else {
                Some(session)
            },
        }
    }

    /// Get session from environment
    pub fn get_session() -> Option<String> {
        // Try OP_SESSION_* environment variables (account-specific)
        // 1Password uses OP_SESSION_{account_shorthand}
        for (key, value) in std::env::vars() {
            if key.starts_with("OP_SESSION_") {
                return Some(value);
            }
        }

        // Try generic session file (if user has one)
        if let Some(home) = dirs::home_dir() {
            let session_file = home.join(".op_session");
            if session_file.exists() {
                if let Ok(session) = std::fs::read_to_string(session_file) {
                    let session = session.trim().to_string();
                    if !session.is_empty() {
                        return Some(session);
                    }
                }
            }
        }

        None
    }

    fn run_op(&self, args: &[&str]) -> Result<String> {
        let mut cmd = Command::new("op");
        cmd.args(args);

        // Add session if available
        if let Some(session) = &self.session {
            cmd.env("OP_SESSION", session);
        } else if let Some(session) = Self::get_session() {
            cmd.env("OP_SESSION", session);
        }

        let output = cmd.output().map_err(|e| {
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
            if stderr.contains("not signed in")
                || stderr.contains("session expired")
                || stderr.contains("authorization")
            {
                return Err(SecretsError::BitwardenSessionExpired); // Reusing error type
            }
            return Err(SecretsError::ConfigInvalid(format!(
                "1Password error: {}",
                stderr.trim()
            )));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}

impl Default for OnePasswordProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretProvider for OnePasswordProvider {
    fn name(&self) -> &str {
        "1password"
    }

    fn is_available(&self) -> bool {
        Command::new("op")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn sync(&self) -> Result<Vec<ProviderItem>> {
        // Get list of all items
        let output = self.run_op(&["item", "list", "--format=json"])?;

        let items: Vec<OpItemSummary> = serde_json::from_str(&output)
            .map_err(|e| SecretsError::ConfigInvalid(format!("Invalid JSON from op: {}", e)))?;

        let mut result = Vec::new();
        for item in items {
            if let Some(provider_item) = self.get_item(&item.title)? {
                result.push(provider_item);
            }
        }

        Ok(result)
    }

    fn get_item(&self, name: &str) -> Result<Option<ProviderItem>> {
        let output = self.run_op(&["item", "get", name, "--format=json"]);

        match output {
            Ok(json) => {
                let item: OpItem = serde_json::from_str(&json).map_err(|e| {
                    SecretsError::ConfigInvalid(format!("Invalid JSON from op: {}", e))
                })?;
                Ok(Some(item.into()))
            }
            Err(SecretsError::ConfigInvalid(msg)) if msg.contains("isn't an item") => Ok(None),
            Err(SecretsError::ConfigInvalid(msg)) if msg.contains("not found") => Ok(None),
            Err(e) => Err(e),
        }
    }
}

// 1Password item structures

#[derive(Debug, Deserialize)]
struct OpItemSummary {
    title: String,
}

#[derive(Debug, Deserialize)]
struct OpItem {
    title: String,
    #[serde(default)]
    fields: Vec<OpField>,
    #[serde(default)]
    notes: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OpField {
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    r#type: Option<String>,
}

impl From<OpItem> for ProviderItem {
    fn from(item: OpItem) -> Self {
        let mut fields = Vec::new();

        for field in item.fields {
            // Skip fields without values
            let value = match field.value {
                Some(v) if !v.is_empty() => v,
                _ => continue,
            };

            // Use label if available, otherwise use id
            let name = field
                .label
                .filter(|l| !l.is_empty())
                .or(field.id)
                .unwrap_or_else(|| "unknown".to_string());

            // Map common 1Password field types to our names
            let name = match name.as_str() {
                "username" | "email" => "username".to_string(),
                "password" => "password".to_string(),
                "notesPlain" => "notes".to_string(),
                other => other.to_string(),
            };

            // Skip concealed fields with placeholder values
            if field.r#type.as_deref() == Some("CONCEALED")
                && (value == "••••••••" || value.contains('\u{2022}'))
            {
                continue;
            }

            fields.push((name, value));
        }

        ProviderItem {
            name: item.title,
            fields,
            notes: item.notes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_onepassword_provider_name() {
        let provider = OnePasswordProvider::new();
        assert_eq!(provider.name(), "1password");
    }
}
