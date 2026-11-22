mod crypto;
mod keys;
mod storage;
mod types;

// Re-export only used items
pub use keys::KeysFile;
pub use storage::{load_vault, save_vault};
pub use types::Vault;
#[cfg(test)]
pub use types::VaultItem;

pub(crate) use storage::atomic_write;
