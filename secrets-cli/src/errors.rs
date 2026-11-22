use thiserror::Error;

#[derive(Error, Debug)]
pub enum SecretsError {
    // Daemon errors
    #[error("Daemon not running. Start it with: launchctl load ~/Library/LaunchAgents/com.ai-secrets.daemon.plist")]
    DaemonNotRunning,

    #[error("Failed to connect to daemon: {0}")]
    DaemonConnectionFailed(#[from] std::io::Error),

    #[error("Client not authorized: CDHash not in whitelist")]
    DaemonUnauthorized,

    #[error("Rate limited: {0}")]
    DaemonRateLimited(String),

    #[allow(dead_code)] // Kept for backward compat with daemon protocol
    #[error("Session expired. Please re-authenticate.")]
    SessionExpired,

    // Vault errors
    #[error("Unable to save local storage: {0}")]
    StorageWriteFailed(String),

    #[error("Vault not found at {0}")]
    VaultNotFound(String),

    #[error("Vault corrupted or invalid password")]
    VaultCorrupted,

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    // Bitwarden errors
    #[allow(dead_code)] // Used in BitwardenProvider
    #[error("Bitwarden CLI not installed. Install with: brew install bitwarden-cli")]
    BitwardenNotInstalled,

    #[allow(dead_code)] // Used in BitwardenProvider
    #[error("Bitwarden login failed: {0}")]
    BitwardenLoginFailed(String),

    #[allow(dead_code)] // Reserved for get command
    #[error("Bitwarden item not found: {0}")]
    BitwardenItemNotFound(String),

    #[error("Bitwarden session expired. Run: secrets unlock")]
    BitwardenSessionExpired,

    // Config errors
    #[error("Configuration not found at {0}")]
    ConfigNotFound(String),

    #[error("Configuration invalid: {0}")]
    ConfigInvalid(String),

    // Security
    #[error("SECURITY ALERT: Canary access detected! Possible compromise of trusted_hashes")]
    CanaryTriggered,

    #[allow(dead_code)] // Directory restrictions removed in v3
    #[error("Access denied for directory: {0}")]
    DirectoryNotAllowed(String),

    // Item errors
    #[error("Item not found: {0}")]
    ItemNotFound(String),

    #[error("Field not found: {0}")]
    FieldNotFound(String),

    #[error("Reserved name '{0}' cannot be used")]
    ReservedName(String),

    // Protocol errors
    #[error("Invalid daemon response: {0}")]
    InvalidResponse(String),
}

// Exit codes per spec
impl SecretsError {
    pub fn exit_code(&self) -> i32 {
        match self {
            SecretsError::DaemonNotRunning
            | SecretsError::DaemonConnectionFailed(_) => 3,

            SecretsError::DaemonUnauthorized => 4,

            SecretsError::StorageWriteFailed(_)
            | SecretsError::VaultNotFound(_)
            | SecretsError::VaultCorrupted
            | SecretsError::DecryptionFailed(_)
            | SecretsError::EncryptionFailed(_) => 5,

            SecretsError::BitwardenNotInstalled
            | SecretsError::BitwardenLoginFailed(_)
            | SecretsError::BitwardenItemNotFound(_)
            | SecretsError::BitwardenSessionExpired => 6,

            SecretsError::ConfigNotFound(_)
            | SecretsError::ConfigInvalid(_) => 7,

            SecretsError::CanaryTriggered => 10, // Special security exit code

            _ => 1,
        }
    }
}

pub type Result<T> = std::result::Result<T, SecretsError>;
