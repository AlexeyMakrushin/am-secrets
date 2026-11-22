mod access;
mod auth;
mod background;
mod cli;
mod command_lock;
mod config;
mod daemon;
mod errors;
mod preflight;
mod providers;
mod security;
mod vault;

use clap::Parser;

use cli::{Cli, Commands};
use errors::SecretsError;

fn main() {
    let cli = Cli::parse();

    if matches!(cli.command, Commands::RefreshLocal) {
        std::process::exit(if background::run().is_ok() { 0 } else { 6 });
    }
    background::report();
    let schedule = !matches!(
        &cli.command,
        Commands::Lock
            | Commands::Setup
            | Commands::Trust { .. }
            | Commands::Whitelist
            | Commands::Sync { .. }
            | Commands::Manifest {
                command: cli::ManifestCommand::Apply { dry_run: true, .. }
            }
    );
    let refresh = if matches!(cli.command, Commands::Lock) {
        Ok(())
    } else {
        preflight::refresh()
    };
    if let Err(ref error) = refresh {
        eprintln!("Error: {error}");
    }
    if refresh.is_err()
        && matches!(
            cli.command,
            Commands::Add { .. }
                | Commands::Sync { .. }
                | Commands::Manifest {
                    command: cli::ManifestCommand::Apply { .. }
                }
        )
    {
        std::process::exit(6);
    }

    let mut _command_lock = if matches!(
        cli.command,
        Commands::Status | Commands::Whitelist | Commands::Trust { .. }
    ) {
        None
    } else {
        match command_lock::acquire() {
            Ok(lock) => Some(lock),
            Err(error) => {
                eprintln!("Error: {error}");
                std::process::exit(error.exit_code());
            }
        }
    };

    let result = match cli.command {
        Commands::RefreshLocal => unreachable!(),
        Commands::Manifest { command } => cli::manifest_command(command),
        Commands::Access { command } => cli::access_command(command),
        Commands::Move { from, to } => cli::move_command(&from, &to),

        Commands::Status => cli::status_command(),

        Commands::Setup => cli::setup_command(),

        Commands::Sync { item, field } => cli::sync_command(item.as_deref(), field.as_deref()),

        Commands::Ls { item, field } => cli::ls_command(item.as_deref(), field.as_deref()),

        Commands::Get { item, field } => cli::get_command(&item, &field),

        Commands::Add { item, field, files } => cli::add_command(&item, field.as_deref(), &files),

        Commands::Delete { item, field } => cli::delete_command(&item, field.as_deref()),

        Commands::Unlock => auth::unlock_command(),

        Commands::Lock => auth::lock_command(),

        Commands::Wrap {
            file,
            uses,
            command,
        } => {
            drop(_command_lock.take());
            match cli::wrap_command(file.as_deref(), &uses, &command) {
                Ok(code) => {
                    if code == 0 && refresh.is_ok() {
                        background::schedule();
                    }
                    std::process::exit(code)
                }
                Err(error) => Err(error),
            }
        }

        Commands::Whitelist => {
            // Output shell wrapper functions for whitelisted commands
            // These wrappers call `secrets wrap <cmd>` to inject secrets
            if let Ok(config) = config::Config::load() {
                let secrets_path = config::Config::secrets_dir().join("secrets");
                let secrets_path = secrets_path.to_string_lossy();
                for cmd in &config.whitelist {
                    // Output: cmd() { ~/.secrets/secrets wrap cmd "$@"; }
                    println!("{}() {{ \"{}\" wrap {} \"$@\"; }}", cmd, secrets_path, cmd);
                }
            }
            Ok(())
        }

        Commands::Trust { self_, clean } => cli::trust_command(self_, clean),
    };

    drop(_command_lock);
    if result.is_ok() && schedule && refresh.is_ok() {
        background::schedule();
    }

    if let Err(e) = result {
        eprintln!("\x1b[31mError:\x1b[0m {}", e);

        // Provide helpful messages for common errors
        match &e {
            SecretsError::DaemonNotRunning => {
                eprintln!(
                    "\nTry: launchctl load ~/Library/LaunchAgents/com.ai-secrets.daemon.plist"
                );
            }
            SecretsError::DaemonUnauthorized => {
                eprintln!("\nYour CLI binary is not authorized. Run:");
                eprintln!("  codesign -s - $(which secrets)");
                eprintln!("  secrets trust --self");
            }
            SecretsError::BitwardenSessionExpired => {
                eprintln!("\nRun: secrets unlock");
            }
            SecretsError::ConfigNotFound(_) => {
                eprintln!("\nRun 'secrets setup' to initialize.");
            }
            _ => {}
        }

        std::process::exit(e.exit_code());
    }
}
