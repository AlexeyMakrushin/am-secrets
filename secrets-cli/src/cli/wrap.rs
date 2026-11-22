use crate::{
    access,
    auth::auth_local,
    config::Config,
    errors::{Result, SecretsError},
    vault::{load_vault, KeysFile},
};
use std::os::unix::process::ExitStatusExt;
use std::{env, path::Path, process::Command};

pub const SECRETS_INJECTED_VAR: &str = "SECRETS_INJECTED";

pub fn wrap_command(file: Option<&Path>, uses: &[String], command: &[String]) -> Result<i32> {
    let config = Config::load()?;
    if !uses.is_empty() && file.is_none() {
        return Err(SecretsError::ConfigInvalid(
            "--use requires --file; example: wrap --file main.py --use deepseek:api -- python3"
                .into(),
        ));
    }
    let identity = file.map(access::canonical_file).transpose()?;
    let executable = command
        .first()
        .map(String::as_str)
        .or(identity.as_deref())
        .ok_or_else(|| SecretsError::ConfigInvalid("Provide --file or a command".into()))?;
    if !config.is_whitelisted(executable) {
        return Err(SecretsError::ConfigInvalid(format!(
            "Command '{executable}' is not allowed by whitelist"
        )));
    }
    let lock = crate::command_lock::acquire()?;
    let keys = KeysFile::load(&Config::keys_path())?;
    let auth = auth_local(&config, &keys)?;
    let vault = load_vault(&Config::vault_path(), &auth.master_key)?;
    let available = access::inventory(&vault);
    let mut selected = std::collections::BTreeSet::new();
    for selector in uses {
        for reference in access::selection(selector)? {
            if !selected.insert(reference) {
                return Err(SecretsError::ConfigInvalid(
                    "Duplicate requested field".into(),
                ));
            }
        }
    }
    for r in &selected {
        if !available.contains(r) {
            return Err(SecretsError::FieldNotFound(format!(
                "{}/{}",
                r.item, r.field
            )));
        }
    }
    // Existing enforced basename restrictions remain an additional gate until explicit reset.
    if vault.access.enforced && !selected.is_empty() {
        let program = access::program_name(executable)?;
        if vault
            .access
            .grants
            .get(&program)
            .is_none_or(|refs| !selected.is_subset(refs))
        {
            return Err(SecretsError::ConfigInvalid(
                "Legacy enforced assignments deny requested fields; review access show".into(),
            ));
        }
    }
    access::validate_files(&vault.access)?;
    for r in &selected {
        if !access::file_allowed(&vault.access, r, identity.as_deref().unwrap_or("")) {
            return Err(SecretsError::ConfigInvalid(format!(
                "File is not allowed to request {}/{}",
                r.item, r.field
            )));
        }
    }
    let names = access::names(selected)?;
    let mut cmd = Command::new(which(executable)?);
    if !command.is_empty() {
        if let Some(file) = &identity {
            cmd.arg(file);
        }
        cmd.args(&command[1..]);
    }
    cmd.env_remove("BW_SESSION")
        .env_remove("BW_PASSWORD")
        .env_remove(SECRETS_INJECTED_VAR);
    if let Ok(inherited) = env::var(SECRETS_INJECTED_VAR) {
        for name in inherited.split(',').filter(|name| !name.is_empty()) {
            cmd.env_remove(name);
        }
    }
    // Clear every valid local ENV name, but unrelated invalid fields do not prevent selection.
    for r in available {
        if let Ok(name) = access::env_name(&r) {
            cmd.env_remove(name);
        }
    }
    for (name, r) in &names {
        cmd.env(name, &vault.items[&r.item].fields[&r.field]);
    }
    cmd.env(
        SECRETS_INJECTED_VAR,
        names.keys().cloned().collect::<Vec<_>>().join(","),
    );
    drop(vault);
    drop(auth);
    drop(lock);
    let mut child = cmd
        .spawn()
        .map_err(|e| SecretsError::ConfigInvalid(format!("Failed to execute {executable}: {e}")))?;
    drop(cmd);
    let status = child.wait()?;
    Ok(status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(1)))
}

fn which(command: &str) -> Result<String> {
    if command.contains('/') {
        return Ok(command.into());
    }
    if let Ok(path_var) = env::var("PATH") {
        for dir in env::split_paths(&path_var) {
            let full = dir.join(command);
            if full.is_file() && env::current_exe().ok().as_ref() != Some(&full) {
                return Ok(full.to_string_lossy().into());
            }
        }
    }
    Err(SecretsError::ItemNotFound(format!(
        "Command not found: {command}"
    )))
}
