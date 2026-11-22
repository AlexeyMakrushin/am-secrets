mod bitwarden;
mod keychain;
mod onepassword;

pub use bitwarden::BitwardenProvider;
pub use keychain::KeychainProvider;
pub use onepassword::OnePasswordProvider;

use crate::errors::{Result, SecretsError};

/// Trait for secret providers
///
/// Note: PIN is NOT stored in providers - only in macOS Keychain via daemon
pub trait SecretProvider {
    /// Provider name
    fn name(&self) -> &str;

    /// Check if provider CLI is available
    fn is_available(&self) -> bool;

    /// Sync all items from provider (not commonly used - prefer get_item)
    fn sync(&self) -> Result<Vec<ProviderItem>>;

    /// Get specific item by name
    fn get_item(&self, name: &str) -> Result<Option<ProviderItem>>;

    /// Check if this provider requires a session/password
    fn requires_session(&self) -> bool {
        true
    }
}

/// Item from a provider
#[derive(Debug, Clone)]
pub struct ProviderItem {
    pub name: String,
    pub fields: Vec<(String, String)>,
    pub notes: Option<String>,
}

/// Create provider by name
pub fn create_provider(name: &str, session: Option<String>) -> Result<Box<dyn SecretProvider>> {
    match name {
        "bitwarden" => Ok(Box::new(BitwardenProvider::with_session(
            session.unwrap_or_default(),
        ))),
        "1password" => Ok(Box::new(OnePasswordProvider::with_session(
            session.unwrap_or_default(),
        ))),
        "keychain" => Ok(Box::new(KeychainProvider::new())),
        _ => Err(SecretsError::ConfigInvalid(format!(
            "Unknown provider: '{}'. Valid: bitwarden, 1password, keychain",
            name
        ))),
    }
}

/// List available provider names
pub fn available_providers() -> &'static [&'static str] {
    &["bitwarden", "1password", "keychain"]
}

/// Get install instructions for provider
pub fn install_instructions(provider: &str) -> &'static str {
    match provider {
        "bitwarden" => "Install: brew install bitwarden-cli",
        "1password" => "Install: brew install 1password-cli",
        "keychain" => "Requires macOS",
        _ => "Unknown provider",
    }
}
