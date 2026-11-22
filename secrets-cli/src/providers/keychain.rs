//! macOS Keychain provider
//!
//! Storage format:
//! - Service: `ai-secrets.{item_name}`
//! - Account: `{field_name}`
//! - Password: `{value}`

use std::process::Command;

use crate::errors::{Result, SecretsError};
use crate::providers::{ProviderItem, SecretProvider};

const SERVICE_PREFIX: &str = "ai-secrets.";

pub struct KeychainProvider;

impl KeychainProvider {
    pub fn new() -> Self {
        Self
    }

    /// Get a specific field from Keychain
    fn get_field(&self, item_name: &str, field_name: &str) -> Result<Option<String>> {
        let service = format!("{}{}", SERVICE_PREFIX, item_name);

        let output = Command::new("security")
            .args([
                "find-generic-password",
                "-s",
                &service,
                "-a",
                field_name,
                "-w", // Output password only
            ])
            .output()
            .map_err(|e| SecretsError::ConfigInvalid(format!("Failed to run security: {}", e)))?;

        if output.status.success() {
            let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
            Ok(Some(value))
        } else {
            // Check if it's "not found" vs actual error
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("could not be found") || stderr.contains("SecKeychainSearchCopyNext") {
                Ok(None)
            } else {
                Err(SecretsError::ConfigInvalid(format!(
                    "Keychain error: {}",
                    stderr.trim()
                )))
            }
        }
    }

    /// List all fields for an item by querying Keychain
    fn list_fields(&self, item_name: &str) -> Result<Vec<(String, String)>> {
        let service = format!("{}{}", SERVICE_PREFIX, item_name);
        let mut fields = Vec::new();

        // Use dump-keychain to find all entries with our service
        // Note: This requires Keychain to be unlocked
        let output = Command::new("security")
            .args(["dump-keychain"])
            .output()
            .map_err(|e| SecretsError::ConfigInvalid(format!("Failed to run security: {}", e)))?;

        if !output.status.success() {
            return Ok(fields);
        }

        let dump = String::from_utf8_lossy(&output.stdout);

        // Parse dump output to find entries with our service
        // Format:
        // keychain: "..."
        // class: "genp"
        // attributes:
        //     "svce"<blob>="ai-secrets.myitem"
        //     "acct"<blob>="field-name"

        let mut current_service: Option<String> = None;
        let mut current_account: Option<String> = None;

        for line in dump.lines() {
            let line = line.trim();

            if line.starts_with("\"svce\"") {
                // Service name
                if let Some(start) = line.find("=\"") {
                    if let Some(end) = line[start + 2..].find('"') {
                        current_service = Some(line[start + 2..start + 2 + end].to_string());
                    }
                }
            } else if line.starts_with("\"acct\"") {
                // Account name (our field name)
                if let Some(start) = line.find("=\"") {
                    if let Some(end) = line[start + 2..].find('"') {
                        current_account = Some(line[start + 2..start + 2 + end].to_string());
                    }
                }
            } else if line.starts_with("keychain:") || line.starts_with("class:") {
                // New entry boundary - process previous if matched
                if let (Some(ref svc), Some(ref acct)) = (&current_service, &current_account) {
                    if svc == &service {
                        // Get the actual value
                        if let Ok(Some(value)) = self.get_field(item_name, acct) {
                            fields.push((acct.clone(), value));
                        }
                    }
                }
                if line.starts_with("keychain:") {
                    current_service = None;
                    current_account = None;
                }
            }
        }

        // Don't forget the last entry
        if let (Some(ref svc), Some(ref acct)) = (&current_service, &current_account) {
            if svc == &service {
                if let Ok(Some(value)) = self.get_field(item_name, acct) {
                    fields.push((acct.clone(), value));
                }
            }
        }

        Ok(fields)
    }

    /// List all ai-secrets items in Keychain
    fn list_items(&self) -> Result<Vec<String>> {
        let output = Command::new("security")
            .args(["dump-keychain"])
            .output()
            .map_err(|e| SecretsError::ConfigInvalid(format!("Failed to run security: {}", e)))?;

        if !output.status.success() {
            return Ok(Vec::new());
        }

        let dump = String::from_utf8_lossy(&output.stdout);
        let mut items = std::collections::HashSet::new();

        for line in dump.lines() {
            let line = line.trim();
            if line.starts_with("\"svce\"") {
                if let Some(start) = line.find("=\"") {
                    if let Some(end) = line[start + 2..].find('"') {
                        let service = &line[start + 2..start + 2 + end];
                        if let Some(item_name) = service.strip_prefix(SERVICE_PREFIX) {
                            items.insert(item_name.to_string());
                        }
                    }
                }
            }
        }

        Ok(items.into_iter().collect())
    }
}

impl Default for KeychainProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretProvider for KeychainProvider {
    fn name(&self) -> &str {
        "keychain"
    }

    fn is_available(&self) -> bool {
        // security CLI is part of macOS
        Command::new("security")
            .arg("help")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn requires_session(&self) -> bool {
        // Keychain doesn't need a session - macOS handles auth
        false
    }

    fn sync(&self) -> Result<Vec<ProviderItem>> {
        let item_names = self.list_items()?;
        let mut items = Vec::new();

        for name in item_names {
            if let Some(item) = self.get_item(&name)? {
                items.push(item);
            }
        }

        Ok(items)
    }

    fn get_item(&self, name: &str) -> Result<Option<ProviderItem>> {
        let fields = self.list_fields(name)?;

        if fields.is_empty() {
            return Ok(None);
        }

        Ok(Some(ProviderItem {
            name: name.to_string(),
            fields,
            notes: None, // Keychain doesn't have a notes field per se
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keychain_available() {
        // Should be available on macOS
        let provider = KeychainProvider::new();
        #[cfg(target_os = "macos")]
        assert!(provider.is_available());
        let _ = provider; // Avoid unused warning on non-macOS
    }

    #[test]
    fn test_keychain_no_session() {
        let provider = KeychainProvider::new();
        assert!(!provider.requires_session());
    }
}
