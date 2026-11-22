use crate::{
    access::{self, SecretRef},
    auth,
    config::Config,
    errors::{Result, SecretsError},
    providers,
    vault::{load_vault, save_vault, KeysFile},
};
use std::{collections::BTreeSet, path::PathBuf};

pub fn add_command(input: &str, field: Option<&str>, files: &[PathBuf]) -> Result<()> {
    let (item, selected) = if input.contains(':') && field.is_none() {
        let refs = access::selection(input)?;
        (refs.iter().next().unwrap().item.clone(), Some(refs))
    } else {
        if crate::vault::Vault::is_reserved_name(input) {
            return Err(SecretsError::ReservedName(input.into()));
        }
        (
            input.to_string(),
            field.map(|f| {
                BTreeSet::from([SecretRef {
                    item: input.into(),
                    field: f.into(),
                }])
            }),
        )
    };
    let paths: BTreeSet<_> = files
        .iter()
        .map(|p| access::canonical_file(p))
        .collect::<Result<_>>()?;
    let config = Config::load()?;
    let keys = KeysFile::load(&Config::keys_path())?;
    let (auth, session) = if paths.is_empty() {
        auth::auth_provider_cached(&config, &keys)?
    } else {
        eprintln!(
            "Allow {}{} for files: {}",
            input,
            field.map(|f| format!("/{f}")).unwrap_or_default(),
            paths.iter().cloned().collect::<Vec<_>>().join(", ")
        );
        auth::confirm(&config, &keys)?
    };
    let mut vault = load_vault(&Config::vault_path(), &auth.master_key)?;
    let local: BTreeSet<_> = access::inventory(&vault)
        .into_iter()
        .filter(|r| r.item == item)
        .collect();
    // With --file and an existing item, no implicit import of future fields.
    let mut refs = selected.unwrap_or_else(|| {
        if !paths.is_empty() {
            local.clone()
        } else {
            BTreeSet::new()
        }
    });
    let needs_provider = refs.is_empty() || refs.iter().any(|r| !local.contains(r));
    if needs_provider {
        if auth::provider_requires_session(&config.provider) && session.is_empty() {
            return Err(SecretsError::BitwardenSessionExpired);
        }
        let provider = providers::create_provider(&config.provider, Some(session.to_string()))?;
        let found = provider
            .get_item(&item)?
            .ok_or_else(|| SecretsError::ItemNotFound(item.clone()))?;
        if refs.is_empty() {
            refs.extend(found.fields.iter().map(|(f, _)| SecretRef {
                item: item.clone(),
                field: f.clone(),
            }));
        }
        for r in &refs {
            if !local.contains(r) {
                let value = found
                    .fields
                    .iter()
                    .find(|(f, _)| f == &r.field)
                    .ok_or_else(|| {
                        SecretsError::FieldNotFound(format!("{}/{}", r.item, r.field))
                    })?;
                vault
                    .items
                    .entry(item.clone())
                    .or_default()
                    .fields
                    .insert(r.field.clone(), value.1.clone());
            }
        }
    }
    if refs.is_empty() {
        return Err(SecretsError::FieldNotFound("No fields selected".into()));
    }
    if !paths.is_empty() {
        access::names(refs.clone())?;
        access::grant_files(&mut vault.access, &refs, &paths);
        access::validate_files(&vault.access)?;
    }
    save_vault(&vault, &Config::vault_path(), &auth.master_key)?;
    println!(
        "Connected {} fields; existing values preserved. File permissions {}.",
        refs.len(),
        if paths.is_empty() {
            "unchanged"
        } else {
            "updated"
        }
    );
    Ok(())
}
