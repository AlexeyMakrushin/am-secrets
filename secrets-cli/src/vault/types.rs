use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Vault structure - decrypted content of vault.enc
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vault {
    #[serde(default)]
    pub access: crate::access::AccessPolicy,
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub items: HashMap<String, VaultItem>,
}

fn default_version() -> u32 {
    2
}

impl Default for Vault {
    fn default() -> Self {
        Self {
            access: crate::access::AccessPolicy::default(),
            version: 2,
            items: HashMap::new(),
        }
    }
}

impl Vault {
    /// Create a new vault with canary entry
    pub fn new_with_canary() -> Self {
        let mut vault = Self::default();
        vault.items.insert(
            "__pin".to_string(),
            VaultItem {
                fields: {
                    let mut fields = HashMap::new();
                    fields.insert(
                        "canary".to_string(),
                        "NEVER_ACCESS_THIS_SECURITY_TRAP".to_string(),
                    );
                    fields
                },
                dirs: vec!["*".to_string()],
                meta: Some(ItemMeta {
                    created: chrono_date(),
                    system: Some(true),
                }),
            },
        );
        vault
    }

    /// Get an item by name
    pub fn get_item(&self, name: &str) -> Option<&VaultItem> {
        self.items.get(name)
    }

    /// Get an item mutably
    #[allow(dead_code)] // Reserved for edit command
    pub fn get_item_mut(&mut self, name: &str) -> Option<&mut VaultItem> {
        self.items.get_mut(name)
    }

    /// Add or update an item
    #[allow(dead_code)] // Reserved for add command
    pub fn set_item(&mut self, name: String, item: VaultItem) {
        self.items.insert(name, item);
    }

    /// Remove an item
    #[allow(dead_code)] // Reserved for delete command
    pub fn remove_item(&mut self, name: &str) -> Option<VaultItem> {
        self.items.remove(name)
    }

    /// Check if item name is reserved (starts with __)
    pub fn is_reserved_name(name: &str) -> bool {
        name.starts_with("__")
    }

    /// List all item names (excluding system items)
    #[allow(dead_code)] // Reserved for show command
    pub fn list_items(&self) -> Vec<&String> {
        self.items
            .keys()
            .filter(|k| !k.starts_with("__"))
            .collect()
    }

    /// List all items including system items
    #[allow(dead_code)] // Reserved for debug/admin
    pub fn list_all_items(&self) -> Vec<&String> {
        self.items.keys().collect()
    }
}

/// A single vault item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultItem {
    pub fields: HashMap<String, String>,
    #[serde(default)]
    pub dirs: Vec<String>,
    #[serde(rename = "_meta", skip_serializing_if = "Option::is_none")]
    pub meta: Option<ItemMeta>,
}

impl VaultItem {
    pub fn new() -> Self {
        Self {
            fields: HashMap::new(),
            dirs: Vec::new(),
            meta: None,
        }
    }

    pub fn get_field(&self, name: &str) -> Option<&String> {
        self.fields.get(name)
    }

    #[allow(dead_code)] // Reserved for edit command
    pub fn set_field(&mut self, name: String, value: String) {
        self.fields.insert(name, value);
    }

    #[allow(dead_code)] // Reserved for delete command
    pub fn remove_field(&mut self, name: &str) -> Option<String> {
        self.fields.remove(name)
    }

    #[allow(dead_code)] // Used in sync, reserved for bind command
    pub fn add_dir(&mut self, dir: String) {
        if !self.dirs.contains(&dir) {
            self.dirs.push(dir);
        }
    }

    #[allow(dead_code)] // Reserved for unbind command
    pub fn remove_dir(&mut self, dir: &str) -> bool {
        if let Some(pos) = self.dirs.iter().position(|d| d == dir) {
            self.dirs.remove(pos);
            true
        } else {
            false
        }
    }

    /// Check if this item is allowed for the given directory
    /// v3: directory restrictions removed, always returns true
    pub fn is_allowed_for_dir(&self, _dir: &str) -> bool {
        true
    }
}

impl Default for VaultItem {
    fn default() -> Self {
        Self::new()
    }
}

/// Item metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemMeta {
    pub created: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<bool>,
}

fn chrono_date() -> String {
    // Simple date formatting without chrono dependency
    use std::time::{SystemTime, UNIX_EPOCH};
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    let days = secs / 86400;
    // Approximate date calculation (not perfect but good enough)
    let year = 1970 + (days / 365);
    let day_of_year = days % 365;
    let month = day_of_year / 30 + 1;
    let day = day_of_year % 30 + 1;
    format!("{:04}-{:02}-{:02}", year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vault_with_canary() {
        let vault = Vault::new_with_canary();
        assert!(vault.items.contains_key("__pin"));
        let canary = vault.get_item("__pin").unwrap();
        assert!(canary.fields.contains_key("canary"));
    }

    #[test]
    fn test_reserved_name() {
        assert!(Vault::is_reserved_name("__pin"));
        assert!(Vault::is_reserved_name("__meta"));
        assert!(!Vault::is_reserved_name("myapp"));
        assert!(!Vault::is_reserved_name("_single_underscore"));
    }

    #[test]
    fn test_item_dir_check() {
        let mut item = VaultItem::new();
        item.add_dir("/example/projects/myapp".to_string());

        // v3: directory restrictions removed, always returns true
        assert!(item.is_allowed_for_dir("/example/projects/myapp"));
        assert!(item.is_allowed_for_dir("/example/projects/myapp/src"));
        assert!(item.is_allowed_for_dir("/example/projects/other"));
    }
}
