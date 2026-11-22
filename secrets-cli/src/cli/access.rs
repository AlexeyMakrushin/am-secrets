use super::AccessCommand;
use crate::{
    access, auth,
    config::Config,
    errors::{Result, SecretsError},
    vault::{load_vault, save_vault, KeysFile},
};

pub fn access_command(command: AccessCommand) -> Result<()> {
    let config = Config::load()?;
    let keys = KeysFile::load(&Config::keys_path())?;
    let auth = if matches!(command, AccessCommand::Show) {
        auth::auth_local(&config, &keys)?
    } else {
        eprintln!("Confirm access change: {command:?}");
        auth::confirm(&config, &keys)?.0
    };
    let mut vault = load_vault(&Config::vault_path(), &auth.master_key)?;
    access::validate_files(&vault.access)?;
    match command {
        AccessCommand::Show => {}
        AccessCommand::ResetLegacy => {
            vault.access.enforced = false;
            vault.access.grants.clear();
            save_vault(&vault, &Config::vault_path(), &auth.master_key)?;
        }
        AccessCommand::Open { selection } => {
            let refs = access::selection(&selection)?;
            vault.access.files.retain(|r| {
                !refs.contains(&access::SecretRef {
                    item: r.item.clone(),
                    field: r.field.clone(),
                })
            });
            save_vault(&vault, &Config::vault_path(), &auth.master_key)?;
        }
        AccessCommand::Revoke { selection, files } => {
            let refs = access::selection(&selection)?;
            // Exact stored absolute path is accepted even after a file was deleted.
            let paths: std::collections::BTreeSet<_> = files
                .iter()
                .map(|p| {
                    if p.exists() {
                        access::canonical_file(p)
                    } else if p.is_absolute() {
                        Ok(p.to_string_lossy().into_owned())
                    } else {
                        Err(SecretsError::ConfigInvalid(
                            "For a removed file use its stored absolute path".into(),
                        ))
                    }
                })
                .collect::<Result<_>>()?;
            for r in &refs {
                let rule = vault
                    .access
                    .files
                    .iter_mut()
                    .find(|rule| rule.item == r.item && rule.field == r.field)
                    .ok_or_else(|| {
                        SecretsError::ConfigInvalid(format!(
                            "{}/{} is unrestricted; first set an allow-list with add --file",
                            r.item, r.field
                        ))
                    })?;
                rule.files.retain(|f| !paths.contains(f));
            }
            save_vault(&vault, &Config::vault_path(), &auth.master_key)?;
        }
    }
    println!("Mode: explicit fields only; fields without file rules are unrestricted.");
    if vault.access.enforced {
        println!(
            "Legacy basename restrictions also active; reset only after reviewing file rules."
        );
    }
    for rule in &vault.access.files {
        println!(
            "{} / {}: {}",
            rule.item,
            rule.field,
            if rule.files.is_empty() {
                "DENIED TO ALL".into()
            } else {
                rule.files.iter().cloned().collect::<Vec<_>>().join(", ")
            }
        );
    }
    Ok(())
}

/// A policy move is one authenticated write, including rules for removed fields.
pub fn move_command(from: &std::path::Path, to: &std::path::Path) -> Result<()> {
    let config = Config::load()?;
    let keys = KeysFile::load(&Config::keys_path())?;
    let current = auth::auth_local(&config, &keys)?;
    let mut vault = load_vault(&Config::vault_path(), &current.master_key)?;
    access::validate_files(&vault.access)?;
    let target = access::canonical_file(to)?;
    let expanded = if let Some(rest) = from.to_str().and_then(|s| s.strip_prefix("~/")) {
        dirs::home_dir()
            .ok_or_else(|| SecretsError::ConfigInvalid("Home unavailable".into()))?
            .join(rest)
    } else {
        from.to_path_buf()
    };
    // Prefer the exact stored path, even if it is now a symlink to another file.
    let literal = expanded
        .to_str()
        .ok_or_else(|| SecretsError::ConfigInvalid("File path must be UTF-8".into()))?;
    let source = if vault.access.files.iter().any(|r| r.files.contains(literal)) {
        literal.to_owned()
    } else if expanded.exists() {
        access::canonical_file(&expanded)?
    } else {
        return Err(SecretsError::ConfigInvalid(
            "No permissions for OLD; copy its full path from secrets access show".into(),
        ));
    };
    if source == target {
        return Err(SecretsError::ConfigInvalid(
            "OLD and NEW identify the same file; nothing to move".into(),
        ));
    }
    let affected: Vec<_> = vault
        .access
        .files
        .iter()
        .enumerate()
        .filter(|(_, r)| r.files.contains(&source))
        .map(|(i, _)| i)
        .collect();
    if affected.is_empty() {
        return Err(SecretsError::ConfigInvalid(
            "No permissions for OLD; inspect secrets access show".into(),
        ));
    }
    eprintln!("Move permissions: {source} -> {target}");
    for &index in &affected {
        let rule = &vault.access.files[index];
        eprintln!("  {} / {}", rule.item, rule.field);
    }
    // Always demand a fresh password after the user can review the exact change.
    let approved = auth::confirm(&config, &keys)?.0;
    if access::canonical_file(to)? != target {
        return Err(SecretsError::ConfigInvalid(
            "NEW changed during confirmation; retry".into(),
        ));
    }
    for index in &affected {
        let rule = &mut vault.access.files[*index];
        rule.files.remove(&source);
        rule.files.insert(target.clone());
    }
    save_vault(&vault, &Config::vault_path(), &approved.master_key)?;
    println!(
        "Moved {} field permissions. Secret values unchanged; files on disk were not moved.",
        affected.len()
    );
    Ok(())
}
