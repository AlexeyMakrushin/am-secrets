use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

use crate::config::Config;
use crate::daemon::DaemonClient;
use crate::errors::{Result, SecretsError};
use crate::providers;
use crate::security::SecretKey;
use crate::vault::{save_vault, KeysFile, Vault};

pub fn setup_command() -> Result<()> {
    let title = format!("am-secrets v{} Setup", env!("CARGO_PKG_VERSION"));
    println!("{title}");
    println!("{}\n", "=".repeat(title.len()));

    let keys_path = Config::keys_path();
    let vault_path = Config::vault_path();
    let config_path = Config::config_path();
    for path in [&keys_path, &vault_path, &config_path] {
        match fs::symlink_metadata(path) {
            Ok(_) => {
                return Err(SecretsError::ConfigInvalid(format!(
                    "Setup found an existing file at {}. Use secrets unlock for an existing vault.",
                    path.display()
                )))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(SecretsError::ConfigInvalid(format!(
                    "Cannot inspect {}: {error}",
                    path.display()
                )))
            }
        }
    }

    // Check daemon (with auto-start)
    print!("Checking daemon... ");
    io::stdout().flush().ok();
    let socket = DaemonClient::default_socket_path();
    let client = DaemonClient::new(socket.clone());
    match client.ping() {
        Ok(true) => println!("\x1b[32mOK\x1b[0m"),
        Ok(false) | Err(SecretsError::DaemonNotRunning) => {
            println!("\x1b[31mFAILED\x1b[0m");
            println!("\nCould not start daemon. Please check:");
            println!("  1. Run: ./install.sh");
            println!("  2. Or manually: launchctl load ~/Library/LaunchAgents/com.ai-secrets.daemon.plist");
            return Err(SecretsError::DaemonNotRunning);
        }
        Err(e) => {
            println!("\x1b[31mERROR\x1b[0m");
            return Err(e);
        }
    }

    // Provider selection
    println!("\nSelect secret provider:");
    println!("  1. bitwarden  - Bitwarden (bw CLI)");
    println!("  2. 1password  - 1Password (op CLI)");
    println!("  3. keychain   - macOS Keychain (native)");
    print!("\nChoice [1-3, default=1]: ");
    io::stdout().flush().ok();

    let mut input = String::new();
    io::stdin().read_line(&mut input).ok();
    let provider = match input.trim() {
        "2" | "1password" => "1password",
        "3" | "keychain" => "keychain",
        _ => "bitwarden",
    };

    println!("Selected provider: \x1b[36m{}\x1b[0m", provider);

    // Check provider availability
    print!("Checking {} CLI... ", provider);
    io::stdout().flush().ok();
    let p = providers::create_provider(provider, None)?;
    if !p.is_available() {
        println!("\x1b[31mNOT FOUND\x1b[0m");
        println!("\n{}", providers::install_instructions(provider));
        return Err(SecretsError::ConfigInvalid(format!(
            "{} CLI not available",
            provider
        )));
    }
    println!("\x1b[32mOK\x1b[0m");

    // Provider-specific configuration
    let mut config = Config::default();
    config.provider = provider.to_string();
    if std::env::var_os("SECRETS_HOME").is_some() {
        config.daemon.socket = socket;
    }

    if provider == "bitwarden" {
        // 1. Server URL (required - no default)
        println!("\nBitwarden server URL (e.g., vault.bitwarden.com or your self-hosted):");
        print!("Server: ");
        io::stdout().flush().ok();
        let mut input = String::new();
        io::stdin().read_line(&mut input).ok();
        let server = input.trim().to_string();
        if server.is_empty() {
            return Err(SecretsError::ConfigInvalid(
                "Server URL is required. Use vault.bitwarden.com for cloud or your server URL."
                    .to_string(),
            ));
        }
        config.bitwarden.server = Some(server);

        // 2. Email (required)
        println!("\nBitwarden account email:");
        print!("Email: ");
        io::stdout().flush().ok();
        let mut input = String::new();
        io::stdin().read_line(&mut input).ok();
        let email = input.trim().to_string();
        if email.is_empty() {
            return Err(SecretsError::ConfigInvalid("Email is required".to_string()));
        }
        config.bitwarden.email = Some(email);
    } else if provider == "1password" {
        // Get 1Password account
        println!("\n1Password account (e.g., my.1password.com, Enter to skip):");
        print!("Account: ");
        io::stdout().flush().ok();
        let mut input = String::new();
        io::stdin().read_line(&mut input).ok();
        let account = input.trim().to_string();
        if !account.is_empty() {
            config.onepassword.account = Some(account);
        }
    }

    // 3. Password (for key wrapping / recovery)
    let password_prompt = match provider {
        "bitwarden" => "\nBitwarden master password:",
        "1password" => "\n1Password master password:",
        "keychain" => "\nCreate a recovery password (for vault encryption):",
        _ => "\nProvider password:",
    };
    println!("{}", password_prompt);
    print!("Password: ");
    io::stdout().flush().ok();
    let password = zeroize::Zeroizing::new(read_password()?);
    if password.is_empty() {
        return Err(SecretsError::ConfigInvalid(
            "Password is required".to_string(),
        ));
    }

    // Check the provider while setup is still retryable.
    print!("\nChecking provider credentials... ");
    io::stdout().flush().ok();
    let session = zeroize::Zeroizing::new(crate::auth::unlock_provider(&password, &config)?);
    if !crate::auth::provider_session_valid(&config, &session)? {
        return Err(SecretsError::BitwardenSessionExpired);
    }
    println!("\x1b[32mOK\x1b[0m");

    let master_key = SecretKey::generate();
    let keys = KeysFile::new_bw_only(&master_key, &password)?;
    drop(password);

    // Add own CDHash to whitelist
    print!("Adding CLI to whitelist... ");
    io::stdout().flush().ok();
    if let Err(e) = add_self_to_whitelist() {
        println!("\x1b[33mSKIPPED\x1b[0m ({})", e);
    } else {
        println!("\x1b[32mOK\x1b[0m");
    }

    // The command lock is held by the caller. Only files created by this setup
    // are rolled back if an ordinary write or daemon error interrupts it.
    let mut created = Vec::new();
    let initialized = (|| -> Result<()> {
        keys.save(&keys_path)?;
        created.push(&keys_path);
        save_vault(&Vault::new_with_canary(), &vault_path, &master_key)?;
        created.push(&vault_path);
        config.save()?;
        created.push(&config_path);
        client.set_state(
            &crate::auth::context(&config, &keys)?,
            &master_key,
            &session,
        )
    })();
    if let Err(error) = initialized {
        for path in created.into_iter().rev() {
            if let Err(cleanup_error) = fs::remove_file(path) {
                eprintln!("Setup could not remove {}: {cleanup_error}", path.display());
            }
        }
        return Err(error);
    }
    drop(session);
    drop(master_key);

    println!("\nAdd secrets to PATH in .zshrc? [Y/n]: ");
    io::stdout().flush().ok();
    let mut input = String::new();
    let add_shell = io::stdin().read_line(&mut input).is_ok_and(|n| n > 0)
        && (input.trim().is_empty()
            || matches!(input.trim().to_ascii_lowercase().as_str(), "y" | "yes"));

    if add_shell {
        match add_shell_integration() {
            Ok(true) => println!("\x1b[32mPATH updated in .zshrc\x1b[0m"),
            Ok(false) => println!("\x1b[33mPATH is already configured in .zshrc\x1b[0m"),
            Err(e) => println!("\x1b[31mFailed to update PATH in .zshrc:\x1b[0m {}", e),
        }
    }

    println!("\n\x1b[32mSetup complete!\x1b[0m");
    println!("\nNext steps:");
    println!("  1. Run 'secrets add \"<item>\" \"<field>\"' to add secrets from provider");
    println!("  2. Run 'secrets ls' to view your vault");
    println!("  3. Run 'secrets get \"<item>\" \"<field>\"' to retrieve a secret");

    if add_shell {
        println!(
            "\n\x1b[33mRestart your terminal or run:\x1b[0m source \"${{ZDOTDIR:-$HOME}}/.zshrc\""
        );
    }

    Ok(())
}

fn read_password() -> Result<String> {
    rpassword::read_password()
        .map_err(|e| SecretsError::ConfigInvalid(format!("Failed to read password: {}", e)))
}

fn add_self_to_whitelist() -> Result<()> {
    use std::process::Command;

    // Get our own path
    let exe = std::env::current_exe().map_err(|e| SecretsError::ConfigInvalid(e.to_string()))?;

    // Get CDHash using codesign
    let output = Command::new("codesign")
        .args(["-dvvv", &exe.to_string_lossy()])
        .output()
        .map_err(|e| SecretsError::ConfigInvalid(e.to_string()))?;

    let stderr = String::from_utf8_lossy(&output.stderr);

    // Find CDHash line
    for line in stderr.lines() {
        if line.contains("CDHash=") {
            if let Some(hash) = line.split('=').nth(1) {
                // Append to trusted_hashes
                let path = Config::trusted_hashes_path();
                let mut content = match fs::read_to_string(&path) {
                    Ok(content) => content,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        "# Trusted CDHashes for ai-secrets\n".to_string()
                    }
                    Err(error) => {
                        return Err(SecretsError::ConfigInvalid(format!(
                            "Could not read trusted_hashes: {error}"
                        )))
                    }
                };

                if !content.contains(hash) {
                    if !content.ends_with('\n') {
                        content.push('\n');
                    }
                    content.push_str(&format!(
                        "{hash} secrets-cli v{}\n",
                        env!("CARGO_PKG_VERSION")
                    ));
                    crate::vault::atomic_write(&path, content.as_bytes())?;
                }
                return Ok(());
            }
        }
    }

    Err(SecretsError::ConfigInvalid(
        "Could not extract CDHash".to_string(),
    ))
}

fn add_shell_integration() -> Result<bool> {
    const START: &str = "# >>> ai-secrets >>>";
    const END: &str = "# <<< ai-secrets <<<";
    const MALFORMED: &str =
        "The am-secrets markers in .zshrc are unbalanced. Fix the markers to update PATH.";
    let zsh_directory = std::env::var_os("ZDOTDIR")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(dirs::home_dir)
        .ok_or_else(|| SecretsError::ConfigInvalid("Could not find .zshrc directory".into()))?;
    let path = zsh_directory.join(".zshrc");
    let (original, permissions) = match fs::read_to_string(&path) {
        Ok(content) => (content, Some(fs::metadata(&path)?.permissions())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => (String::new(), None),
        Err(error) => {
            return Err(SecretsError::ConfigInvalid(format!(
                "Could not read .zshrc: {error}"
            )))
        }
    };
    let block = format!("{START}\nexport PATH=\"$HOME/.secrets:$PATH\"\n{END}\n");
    let mut edited = String::new();
    let mut inside = false;
    let mut replaced = false;
    for line in original.split_inclusive('\n') {
        match line.trim_end_matches(['\r', '\n']) {
            START if !inside => {
                inside = true;
                if !replaced {
                    edited.push_str(&block);
                    replaced = true;
                }
            }
            END if inside => inside = false,
            START | END => return Err(SecretsError::ConfigInvalid(MALFORMED.into())),
            _ if !inside => edited.push_str(line),
            _ => {}
        }
    }
    if inside {
        return Err(SecretsError::ConfigInvalid(MALFORMED.into()));
    }
    if !replaced {
        if !edited.is_empty() && !edited.ends_with('\n') {
            edited.push('\n');
        }
        edited.push_str(&block);
    }
    if edited == original {
        return Ok(false);
    }
    crate::vault::atomic_write(&path, edited.as_bytes())?;
    if let Some(permissions) = permissions {
        fs::set_permissions(path, permissions)?;
    }
    Ok(true)
}
