//! Portable references only. Values are fetched locally and committed as one vault.
use super::ManifestCommand;
use crate::{
    access::{self, AccessPolicy, SecretRef},
    auth::{auth_local, auth_provider_cached},
    config::Config,
    errors::{Result, SecretsError},
    providers,
    vault::{load_vault, save_vault, KeysFile},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs::OpenOptions,
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

const MAX_BYTES: u64 = 1024 * 1024;

#[derive(Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct Source {
    provider: String,
    server: String,
    email: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u32,
    source: Source,
    entries: Vec<SecretRef>,
    access: AccessPolicy,
}

fn source(config: &Config) -> Result<Source> {
    if config.provider != "bitwarden" {
        return Err(invalid(
            "Manifest transfer currently supports Bitwarden only",
        ));
    }
    let server = config
        .bitwarden
        .server
        .as_deref()
        .unwrap_or("")
        .trim()
        .trim_end_matches('/')
        .to_ascii_lowercase();
    let email = config
        .bitwarden
        .email
        .as_deref()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if server.is_empty() || email.is_empty() {
        return Err(invalid("Configure the Bitwarden server and email first"));
    }
    Ok(Source {
        provider: "bitwarden".into(),
        server,
        email,
    })
}
fn invalid(message: &str) -> SecretsError {
    SecretsError::ConfigInvalid(message.into())
}

fn validate(manifest: &Manifest, config: &Config, with_access: bool) -> Result<()> {
    if ![1, 2].contains(&manifest.version) {
        return Err(invalid("Unsupported manifest version"));
    }
    if manifest.source != source(config)? {
        return Err(invalid(
            "Manifest source does not match the configured Bitwarden account/server",
        ));
    }
    let references: BTreeSet<_> = manifest.entries.iter().cloned().collect();
    if references.len() != manifest.entries.len() {
        return Err(invalid("Duplicate manifest entries"));
    }
    access::names(references.clone())?;
    for (program, refs) in &manifest.access.grants {
        if access::program_name(program)? != *program || !refs.is_subset(&references) {
            return Err(invalid("Invalid manifest assignments"));
        }
    }
    access::validate_files(&manifest.access)?;
    if with_access {
        for rule in &manifest.access.files {
            for file in &rule.files {
                if access::canonical_file(Path::new(file))? != *file {
                    return Err(invalid("Manifest file path is not canonical"));
                }
            }
        }
        access::validate(&manifest.access, &references, config)?;
    }
    Ok(())
}

fn read(path: &Path) -> Result<Manifest> {
    if !std::fs::metadata(path)
        .map_err(|_| invalid("Cannot inspect manifest file"))?
        .is_file()
    {
        return Err(invalid("Manifest must be a regular file"));
    }
    let file = std::fs::File::open(path).map_err(|_| invalid("Cannot open manifest file"))?;
    if !file
        .metadata()
        .map_err(|_| invalid("Cannot inspect manifest file"))?
        .is_file()
    {
        return Err(invalid("Manifest must be a regular file"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid("Cannot read manifest file"))?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(invalid("Manifest exceeds 1 MiB"));
    }
    // Never echo parser fragments: a malformed input might contain actual values.
    let metadata: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| invalid("Invalid manifest schema; only metadata fields are allowed"))?;
    if metadata["version"] == 2 && metadata["access"].get("files").is_none() {
        return Err(invalid("Version 2 requires explicit file rules"));
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| invalid("Invalid manifest schema; only metadata fields are allowed"))
}

pub fn manifest_command(command: ManifestCommand) -> Result<()> {
    let config = Config::load()?;
    match command {
        ManifestCommand::Export { file } => {
            let identity = source(&config)?;
            let keys = KeysFile::load(&Config::keys_path())?;
            let auth = auth_local(&config, &keys)?;
            let vault = load_vault(&Config::vault_path(), &auth.master_key)?;
            let manifest = Manifest {
                version: 2,
                source: identity,
                entries: access::inventory(&vault).into_iter().collect(),
                access: vault.access,
            };
            validate(&manifest, &config, false)?;
            let bytes = serde_json::to_vec_pretty(&manifest)
                .map_err(|_| invalid("Cannot serialize manifest"))?;
            if bytes.len() as u64 > MAX_BYTES {
                return Err(invalid("Manifest exceeds 1 MiB"));
            }
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&file)
                .map_err(|_| {
                    invalid("Cannot create manifest; choose a new file in an existing directory")
                })?;
            if let Err(error) = output.write_all(&bytes).and_then(|_| output.sync_all()) {
                let _ = std::fs::remove_file(&file);
                return Err(SecretsError::StorageWriteFailed(error.to_string()));
            }
            println!(
                "Exported {} field references; no secret values. Source identity is included.",
                manifest.entries.len()
            );
        }
        ManifestCommand::Apply {
            file,
            with_access,
            dry_run,
        } => {
            let manifest = read(&file)?;
            validate(&manifest, &config, with_access)?;
            if dry_run {
                println!("Valid manifest: {} fields; assignments {}. No values fetched; vault unchanged.", manifest.entries.len(), if with_access { "will be replaced" } else { "will be preserved" });
                return Ok(());
            }
            let keys = KeysFile::load(&Config::keys_path())?;
            let (auth, session) = if with_access {
                eprintln!(
                    "Replace access from manifest {} (version {}); review --dry-run first",
                    file.display(),
                    manifest.version
                );
                crate::auth::confirm(&config, &keys)?
            } else {
                auth_provider_cached(&config, &keys)?
            };
            if session.is_empty() {
                return Err(SecretsError::BitwardenSessionExpired);
            }
            let mut vault = load_vault(&Config::vault_path(), &auth.master_key)?;
            let provider = providers::create_provider(&config.provider, Some(session.to_string()))?;
            let items: BTreeSet<_> = manifest.entries.iter().map(|r| r.item.as_str()).collect();
            for item in items {
                let found = provider
                    .get_item(item)?
                    .ok_or_else(|| SecretsError::ItemNotFound(item.into()))?;
                for reference in manifest.entries.iter().filter(|r| r.item == item) {
                    let value = found
                        .fields
                        .iter()
                        .find(|(name, _)| name == &reference.field)
                        .ok_or_else(|| {
                            SecretsError::FieldNotFound(format!(
                                "{}/{}",
                                reference.item, reference.field
                            ))
                        })?;
                    vault
                        .items
                        .entry(item.into())
                        .or_default()
                        .fields
                        .insert(reference.field.clone(), value.1.clone());
                }
            }
            access::names(access::inventory(&vault))?;
            if with_access {
                let previous_files = vault.access.files;
                vault.access = manifest.access;
                // Old manifests cannot silently erase rules they cannot represent.
                if manifest.version == 1 {
                    vault.access.files = previous_files;
                }
            }
            save_vault(&vault, &Config::vault_path(), &auth.master_key)?;
            println!(
                "Applied {} field references atomically; unrelated local fields preserved.",
                manifest.entries.len()
            );
            println!(
                "Assignments: {}",
                if with_access {
                    "replaced from manifest"
                } else {
                    "preserved locally"
                }
            );
        }
    }
    Ok(())
}
