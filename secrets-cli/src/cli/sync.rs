use std::io::{self, IsTerminal, Write};

use crate::auth::{auth_provider_cached, provider_requires_session};
use crate::config::Config;
use crate::errors::{Result, SecretsError};
use crate::providers;
use crate::vault::{load_vault, save_vault, KeysFile};

pub fn sync_command(item: Option<&str>, field: Option<&str>) -> Result<()> {
    println!("Sync from provider");
    let config = Config::load()?;
    let keys = KeysFile::load(&Config::keys_path())?;
    let (auth, session) = if provider_requires_session(&config.provider) {
        auth_provider_cached(&config, &keys)?
    } else {
        (
            crate::auth::auth_local(&config, &keys)?,
            zeroize::Zeroizing::new(String::new()),
        )
    };
    let provider = providers::create_provider(&config.provider, Some(session.to_string()))?;
    let mut vault = load_vault(&Config::vault_path(), &auth.master_key)?;
    if let Some(name) = item {
        let local = vault
            .items
            .get(name)
            .filter(|_| !name.starts_with("__"))
            .ok_or_else(|| SecretsError::ItemNotFound(name.into()))?;
        if let Some(field) = field {
            if !local.fields.contains_key(field) {
                return Err(SecretsError::FieldNotFound(format!("{name}/{field}")));
            }
        }
    } else if field.is_some() {
        return Err(SecretsError::ConfigInvalid(
            "ITEM required with FIELD".into(),
        ));
    }
    let mut registered: Vec<(String, Vec<String>)> = vault
        .items
        .iter()
        .filter(|(name, _)| !name.starts_with("__") && item.is_none_or(|i| i == name.as_str()))
        .map(|(name, local)| {
            let mut fields: Vec<_> = local
                .fields
                .keys()
                .filter(|name| field.is_none_or(|f| f == name.as_str()))
                .cloned()
                .collect();
            fields.sort();
            (name.clone(), fields)
        })
        .collect();
    registered.sort_by(|a, b| a.0.cmp(&b.0));
    let mut missing = Vec::new();
    let mut prepared = 0;
    for (name, fields) in &registered {
        print!("  {name} ({} fields) ... ", fields.len());
        io::stdout().flush()?;
        // Transport/auth/duplicate errors abort: they never imply deletion.
        let remote = provider.get_item(name)?;
        if let Some(remote) = remote {
            let local = vault.items.get_mut(name).expect("registered item");
            let mut updated = 0;
            for field in fields {
                if let Some((_, value)) = remote.fields.iter().find(|(f, _)| f == field) {
                    local.fields.insert(field.clone(), value.clone());
                    updated += 1;
                } else {
                    missing.push(Missing::Field(name.clone(), field.clone()));
                }
            }
            println!("{updated} fields prepared");
            prepared += 1;
        } else {
            println!("missing from provider");
            // A field-scoped sync may remove only that field, not the whole item.
            if let Some(field) = field {
                missing.push(Missing::Field(name.clone(), field.into()));
            } else {
                missing.push(Missing::Item(name.clone()));
            }
        }
    }
    if !missing.is_empty() {
        if config.provider != "bitwarden" {
            return Err(SecretsError::ConfigInvalid("Provider data missing; vault was not changed. Interactive cleanup is supported only for Bitwarden.".into()));
        }
        eprintln!("Missing from provider; proposed local removals:");
        for entry in &missing {
            match entry {
                Missing::Item(name) => eprintln!("  item {name:?} (all its local fields)"),
                Missing::Field(name, field) => eprintln!("  field {name:?} / {field:?}"),
            }
        }
        if !confirm_removal()? {
            return Err(SecretsError::ConfigInvalid("Removal not confirmed; vault was not changed. Run secrets sync in your terminal to review.".into()));
        }
        for entry in &missing {
            match entry {
                Missing::Item(name) => {
                    vault.items.remove(name);
                    crate::access::remove(&mut vault, name, None);
                }
                Missing::Field(name, field) => {
                    if let Some(local) = vault.items.get_mut(name) {
                        local.fields.remove(field);
                    }
                    crate::access::remove(&mut vault, name, Some(field));
                }
            }
        }
    }
    // Only one write after every lookup and the explicit terminal confirmation.
    save_vault(&vault, &Config::vault_path(), &auth.master_key)?;
    println!(
        "Prepared: {prepared}, Errors: 0; local removals: {}. Vault saved.",
        missing.len()
    );
    Ok(())
}

enum Missing {
    Item(String),
    Field(String, String),
}

fn confirm_removal() -> Result<bool> {
    if !io::stdin().is_terminal() {
        return Ok(false);
    }
    eprint!("Remove listed local values? File access rules will be kept. [y/N]: ");
    io::stderr().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    Ok(matches!(
        answer.trim().to_lowercase().as_str(),
        "y" | "yes" | "д" | "да"
    ))
}
