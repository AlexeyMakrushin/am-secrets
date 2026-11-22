use std::fs;
use std::process::Command;

use crate::config::Config;
use crate::errors::{Result, SecretsError};

pub fn trust_command(self_: bool, clean: bool) -> Result<()> {
    if clean {
        return clean_trusted_hashes();
    }

    if !self_ {
        println!("Usage: secrets trust --self");
        println!("       secrets trust --clean");
        println!("\n--self:  Add CLI's CDHash to trusted_hashes");
        println!("--clean: Remove old CDHashes, keep only current CLI");
        return Ok(());
    }

    println!("Adding own CDHash to whitelist...\n");

    // Get our own path
    let exe = std::env::current_exe()
        .map_err(|e| SecretsError::ConfigInvalid(format!("Could not get executable path: {}", e)))?;

    println!("Executable: {}", exe.display());

    // Get CDHash using codesign
    let output = Command::new("codesign")
        .args(["-dvvv", &exe.to_string_lossy()])
        .output()
        .map_err(|e| SecretsError::ConfigInvalid(format!("Could not run codesign: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SecretsError::ConfigInvalid(format!(
            "Binary not signed. Sign with: codesign -s - {}\nError: {}",
            exe.display(),
            stderr
        )));
    }

    let stderr = String::from_utf8_lossy(&output.stderr);

    // Find CDHash line
    let mut cdhash = None;
    for line in stderr.lines() {
        if line.contains("CDHash=") {
            if let Some(hash) = line.split('=').nth(1) {
                cdhash = Some(hash.trim().to_string());
                break;
            }
        }
    }

    let cdhash = cdhash.ok_or_else(|| {
        SecretsError::ConfigInvalid("Could not extract CDHash from codesign output".to_string())
    })?;

    println!("CDHash:     {}", cdhash);

    // Read or create trusted_hashes file
    let path = Config::trusted_hashes_path();
    let mut content = if path.exists() {
        fs::read_to_string(&path).unwrap_or_default()
    } else {
        "# Trusted CDHashes for ai-secrets\n# Format: cdhash comment\n".to_string()
    };

    // Check if already present
    if content.contains(&cdhash) {
        println!("\n\x1b[33mCDHash already in whitelist\x1b[0m");
        return Ok(());
    }

    // Append new hash
    let entry = format!("{} secrets-cli v2.0.0\n", cdhash);
    content.push_str(&entry);

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| SecretsError::ConfigInvalid(format!("Could not create directory: {}", e)))?;
    }

    // Write file
    fs::write(&path, content)
        .map_err(|e| SecretsError::ConfigInvalid(format!("Could not write trusted_hashes: {}", e)))?;

    // Set permissions to 600
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).ok();
    }

    println!("\n\x1b[32mAdded to {}\x1b[0m", path.display());
    println!("\nNote: This is a UX convenience, not a security control.");
    println!("Any user process can modify trusted_hashes.");

    Ok(())
}

/// Remove old CDHashes, keep only the current CLI's hash
fn clean_trusted_hashes() -> Result<()> {
    println!("Cleaning trusted_hashes...\n");

    // Get our own CDHash first
    let exe = std::env::current_exe()
        .map_err(|e| SecretsError::ConfigInvalid(format!("Could not get executable path: {}", e)))?;

    let output = Command::new("codesign")
        .args(["-dvvv", &exe.to_string_lossy()])
        .output()
        .map_err(|e| SecretsError::ConfigInvalid(format!("Could not run codesign: {}", e)))?;

    if !output.status.success() {
        return Err(SecretsError::ConfigInvalid(
            "Binary not signed. Run 'secrets trust --self' first.".to_string(),
        ));
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let mut current_hash = None;
    for line in stderr.lines() {
        if line.contains("CDHash=") {
            if let Some(hash) = line.split('=').nth(1) {
                current_hash = Some(hash.trim().to_string());
                break;
            }
        }
    }

    let current_hash = current_hash.ok_or_else(|| {
        SecretsError::ConfigInvalid("Could not extract CDHash".to_string())
    })?;

    println!("Current CDHash: {}", current_hash);

    // Read existing file
    let path = Config::trusted_hashes_path();
    if !path.exists() {
        println!("\nNo trusted_hashes file found.");
        return Ok(());
    }

    let content = fs::read_to_string(&path)
        .map_err(|e| SecretsError::ConfigInvalid(format!("Could not read file: {}", e)))?;

    // Count old hashes
    let old_count = content
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .filter(|l| !l.starts_with(&current_hash))
        .count();

    if old_count == 0 {
        println!("\nNo old hashes to remove.");
        return Ok(());
    }

    // Create new content with only current hash
    let new_content = format!(
        "# Trusted CDHashes for ai-secrets\n# Format: cdhash comment\n{} secrets-cli v2.0.0\n",
        current_hash
    );

    fs::write(&path, new_content)
        .map_err(|e| SecretsError::ConfigInvalid(format!("Could not write file: {}", e)))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).ok();
    }

    println!("\n\x1b[32mRemoved {} old hash(es)\x1b[0m", old_count);
    println!("Kept current CLI hash: {}", current_hash);

    Ok(())
}
