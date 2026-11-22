mod access;
mod get;
mod manifest;
pub use access::{access_command, move_command};
pub use manifest::manifest_command;
mod add;
mod delete;
mod setup;
mod show;
mod status;
mod sync;
mod trust;
mod wrap;

pub use add::add_command;
pub use delete::delete_command;
pub use get::get_command;
pub use setup::setup_command;
pub use show::ls_command;
pub use status::status_command;
pub use sync::sync_command;
pub use trust::trust_command;
pub use wrap::wrap_command;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "secrets")]
#[command(author = "Alexey Makrushin")]
#[command(version)]
#[command(about = "Local secrets manager for AI agents with Bitwarden sync")]
#[command(long_about = concat!("am-secrets v", env!("CARGO_PKG_VERSION"), " — local secrets launcher.\n\n\
    Syncs secrets from Bitwarden, stores them encrypted locally,\n\
    and provides them to trusted applications at runtime.\n\n\
    Quick start:\n\
    \x20 secrets ls                          # List all items\n\
    \x20 secrets add \"openai\"                # Import all fields\n\
    \x20 secrets add \"openai\" \"api-key\"      # Import one field\n\
    \x20 secrets get \"openai\" \"api-key\"      # Get value (TTY only)\n\
    \x20 secrets wrap --file main.py --use openai:api-key -- python3"))]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Internal detached updater (no interactive authentication)
    #[command(hide = true)]
    RefreshLocal,
    /// Export/apply a list of field references without secret values
    Manifest {
        #[command(subcommand)]
        command: ManifestCommand,
    },
    /// Rebind all field permissions from OLD to NEW; does not move files on disk
    Move {
        #[arg(value_name = "OLD")]
        from: std::path::PathBuf,
        #[arg(value_name = "NEW")]
        to: std::path::PathBuf,
    },
    /// Manage explicit program-to-field assignments
    Access {
        #[command(subcommand)]
        command: AccessCommand,
    },
    /// Show system status (daemon, vault, config)
    Status,

    /// Initial setup — generate unlock key and configure provider
    Setup,

    /// Update existing secrets from provider
    ///
    /// Only updates secrets that already exist in the local vault.
    /// Use 'secrets add' to add new secrets.
    ///
    /// Examples:
    ///   secrets sync                    # Update all secrets
    ///   secrets sync "myapp"            # Update all fields of myapp
    ///   secrets sync "myapp" "api-key"  # Update specific field
    Sync {
        /// Item name (must already exist in vault)
        #[arg(value_name = "ITEM")]
        item: Option<String>,
        /// Field name (must already exist in item)
        #[arg(value_name = "FIELD")]
        field: Option<String>,
    },

    /// List vault contents (items, fields, values)
    ///
    /// Examples:
    ///   secrets ls                  # List all items
    ///   secrets ls "myapp"          # Show item fields (masked)
    ///   secrets ls "myapp" "token"  # Show specific field value
    #[command(name = "ls")]
    Ls {
        /// Item name
        #[arg(value_name = "ITEM")]
        item: Option<String>,
        /// Field name
        #[arg(value_name = "FIELD")]
        field: Option<String>,
    },

    /// Get a secret value (for scripts and env vars, TTY only)
    ///
    /// Returns only the value, no formatting. Requires interactive terminal.
    /// Use in scripts:
    ///   export API_KEY=$(secrets get "openai" "api-key")
    ///
    /// Examples:
    ///   secrets get "myapp" "password"
    ///   secrets get "GitHub Work" "access token"
    Get {
        /// Item name in vault
        #[arg(value_name = "ITEM")]
        item: String,
        /// Field name in item
        #[arg(value_name = "FIELD")]
        field: String,
    },

    /// Add secret(s) from provider (Bitwarden)
    ///
    /// Without field: imports ALL fields from provider item.
    /// With field: imports only the specified field.
    ///
    /// Examples:
    ///   secrets add "openai"              # Import all fields
    ///   secrets add "openai" "api-key"    # Import one field
    Add {
        /// Item name in provider
        #[arg(value_name = "ITEM")]
        item: String,
        /// Field name in provider (omit to import all)
        #[arg(value_name = "FIELD")]
        field: Option<String>,
        /// Bind selected fields to these exact files; requires a fresh password
        #[arg(long = "file", action = clap::ArgAction::Append)]
        files: Vec<std::path::PathBuf>,
    },

    /// Delete item or field from vault
    ///
    /// Examples:
    ///   secrets delete "myapp"            # Delete entire item
    ///   secrets delete "myapp" "old-key"  # Delete specific field
    Delete {
        /// Item name
        #[arg(value_name = "ITEM")]
        item: String,
        /// Field name to delete
        #[arg(value_name = "FIELD")]
        field: Option<String>,
    },

    /// Run a file with explicitly requested ITEM:FIELD1,FIELD2 selectors
    Wrap {
        /// Canonical identity of the executed script or binary
        #[arg(long)]
        file: Option<std::path::PathBuf>,
        /// One option, multiple selectors separated by spaces; no implicit fields
        #[arg(long = "use", num_args = 1.., value_name = "ITEM:FIELDS")]
        uses: Vec<String>,
        /// Interpreter followed by script arguments, after --; without it run file directly
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },

    /// Show legacy shell functions. They pass no secret fields.
    /// Use wrap --file FILE --use ITEM:FIELDS for explicit access.
    Whitelist,

    /// Manage trusted CLI binaries (CDHash whitelist)
    ///
    /// Only trusted binaries can access secrets via daemon.
    ///
    /// Examples:
    ///   secrets trust --self          # Trust current CLI
    ///   secrets trust --self --clean  # Trust current, remove old
    Trust {
        /// Add current CLI to whitelist
        #[arg(long = "self")]
        self_: bool,
        /// Remove old hashes, keep only current CLI
        #[arg(long)]
        clean: bool,
    },

    /// Unlock the local vault and provider until the daemon stops
    Unlock,
    /// Clear the local key and provider session from daemon memory
    Lock,
}

#[derive(Subcommand, Debug)]
pub enum AccessCommand {
    /// Show explicit-field rules (no values)
    Show,
    /// Remove files from a field rule; removing the last keeps it denied to everyone
    Revoke {
        selection: String,
        #[arg(long = "file", required = true)]
        files: Vec<std::path::PathBuf>,
    },
    /// Allow any file to explicitly request selected fields; requires password
    Open { selection: String },
    /// Remove obsolete basename restrictions after reviewing file rules; requires password
    ResetLegacy,
}

#[derive(Subcommand)]
pub enum ManifestCommand {
    /// Create a new metadata-only JSON file (no overwrite)
    Export { file: std::path::PathBuf },
    /// Fetch listed fields into this machine's vault; preserve unrelated fields
    Apply {
        file: std::path::PathBuf,
        /// Replace program assignments and mode from this manifest
        #[arg(long)]
        with_access: bool,
        /// Validate metadata only, without unlock or fetching field values
        #[arg(long)]
        dry_run: bool,
    },
}
