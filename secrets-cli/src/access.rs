//! Explicit field assignments; this is ENV routing, not process isolation.
use crate::{
    errors::{Result, SecretsError},
    vault::Vault,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretRef {
    pub item: String,
    pub field: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessPolicy {
    #[serde(default)]
    pub files: Vec<FileRule>,
    pub enforced: bool,
    #[serde(deserialize_with = "read_grants")]
    pub grants: BTreeMap<String, BTreeSet<SecretRef>>,
}

fn read_grants<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<BTreeMap<String, BTreeSet<SecretRef>>, D::Error> {
    struct Visitor;
    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = BTreeMap<String, BTreeSet<SecretRef>>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("unique program assignments")
        }
        fn visit_map<M: serde::de::MapAccess<'de>>(
            self,
            mut map: M,
        ) -> std::result::Result<Self::Value, M::Error> {
            let mut grants = BTreeMap::new();
            while let Some((program, refs)) = map.next_entry::<String, Vec<SecretRef>>()? {
                let count = refs.len();
                let refs: BTreeSet<_> = refs.into_iter().collect();
                if refs.len() != count || grants.insert(program, refs).is_some() {
                    return Err(serde::de::Error::custom("Duplicate assignments"));
                }
            }
            Ok(grants)
        }
    }
    deserializer.deserialize_map(Visitor)
}

pub fn program_name(command: &str) -> Result<String> {
    let name = Path::new(command)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-+".contains(c))
    {
        return Err(SecretsError::ConfigInvalid("Invalid program name".into()));
    }
    Ok(name.into())
}

pub fn env_name(reference: &SecretRef) -> Result<String> {
    if reference.item.is_empty()
        || reference.field.is_empty()
        || Vault::is_reserved_name(&reference.item)
        || reference
            .item
            .chars()
            .chain(reference.field.chars())
            .any(char::is_control)
    {
        return Err(SecretsError::ConfigInvalid(
            "Invalid or reserved item/field name".into(),
        ));
    }
    let normalize = |s: &str| {
        s.chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_uppercase()
                } else {
                    '_'
                }
            })
            .collect::<String>()
    };
    let name = format!(
        "{}_{}",
        normalize(&reference.item),
        normalize(&reference.field)
    );
    // exec accepts digit-leading names; keep the existing mapping (2captcha/api).
    // Shell assignment syntax is narrower than the child process environment.
    if matches!(
        name.as_str(),
        "BW_SESSION" | "BW_PASSWORD" | "SECRETS_INJECTED" | "BASH_ENV"
    ) || name.starts_with("SECRETS_")
        || name.starts_with("DYLD_")
        || name.starts_with("LD_")
    {
        return Err(SecretsError::ConfigInvalid(
            "Secret maps to a reserved or invalid ENV name".into(),
        ));
    }
    Ok(name)
}

/// Validate all references at once so ambiguous ENV names never pick a random value.
pub fn names(
    references: impl IntoIterator<Item = SecretRef>,
) -> Result<BTreeMap<String, SecretRef>> {
    let mut names = BTreeMap::new();
    for reference in references {
        let name = env_name(&reference)?;
        if names.insert(name.clone(), reference).is_some() {
            return Err(SecretsError::ConfigInvalid(format!(
                "Ambiguous or duplicate ENV name: {name}"
            )));
        }
    }
    Ok(names)
}

pub fn inventory(vault: &Vault) -> BTreeSet<SecretRef> {
    vault
        .items
        .iter()
        .filter(|(name, _)| !Vault::is_reserved_name(name))
        .flat_map(|(name, item)| {
            item.fields.keys().map(move |field| SecretRef {
                item: name.clone(),
                field: field.clone(),
            })
        })
        .collect()
}

pub fn validate(
    policy: &AccessPolicy,
    available: &BTreeSet<SecretRef>,
    config: &crate::config::Config,
) -> Result<()> {
    for (program, refs) in &policy.grants {
        if program_name(program)? != *program || !config.is_whitelisted(program) {
            return Err(SecretsError::ConfigInvalid(format!(
                "Program '{program}' is not in the local whitelist"
            )));
        }
        if refs.iter().any(|r| !available.contains(r)) {
            return Err(SecretsError::ConfigInvalid(format!(
                "Assignment for '{program}' references an unavailable field"
            )));
        }
    }
    Ok(())
}

pub fn remove(vault: &mut Vault, item: &str, field: Option<&str>) {
    for refs in vault.access.grants.values_mut() {
        refs.retain(|r| r.item != item || field.is_some_and(|f| r.field != f));
    }
}

/// Parse one explicit selector, never interpreting a bare item as all fields.
pub fn selection(selector: &str) -> Result<BTreeSet<SecretRef>> {
    let (item, fields) = selector.split_once(':').ok_or_else(|| {
        SecretsError::ConfigInvalid("Use ITEM:FIELD1,FIELD2; fields must be explicit".into())
    })?;
    if item.is_empty() || fields.is_empty() || fields.contains(':') {
        return Err(SecretsError::ConfigInvalid(
            "Invalid ITEM:FIELD1,FIELD2 selector".into(),
        ));
    }
    let mut refs = BTreeSet::new();
    for field in fields.split(',') {
        let reference = SecretRef {
            item: item.into(),
            field: field.into(),
        };
        env_name(&reference)?;
        if !refs.insert(reference) {
            return Err(SecretsError::ConfigInvalid(
                "Duplicate requested field".into(),
            ));
        }
    }
    Ok(refs)
}

pub fn canonical_file(path: &Path) -> Result<String> {
    let expanded = if let Some(rest) = path.to_str().and_then(|p| p.strip_prefix("~/")) {
        dirs::home_dir()
            .ok_or_else(|| SecretsError::ConfigInvalid("Home unavailable".into()))?
            .join(rest)
    } else {
        path.to_path_buf()
    };
    let full = std::fs::canonicalize(&expanded).map_err(|_| {
        SecretsError::ConfigInvalid(format!("File does not exist: {}", path.display()))
    })?;
    if !full.is_file() {
        return Err(SecretsError::ConfigInvalid(
            "--file must name a regular file".into(),
        ));
    }
    let text = full
        .to_str()
        .ok_or_else(|| SecretsError::ConfigInvalid("File path must be UTF-8".into()))?;
    if text.chars().any(char::is_control) {
        return Err(SecretsError::ConfigInvalid(
            "Control character in file path".into(),
        ));
    }
    Ok(text.into())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileRule {
    pub item: String,
    pub field: String,
    #[serde(deserialize_with = "read_files")]
    pub files: BTreeSet<String>,
}

pub fn validate_files(policy: &AccessPolicy) -> Result<()> {
    let mut unique = BTreeSet::new();
    for rule in &policy.files {
        let reference = SecretRef {
            item: rule.item.clone(),
            field: rule.field.clone(),
        };
        env_name(&reference)?;
        if !unique.insert(reference) {
            return Err(SecretsError::ConfigInvalid("Duplicate file rule".into()));
        }
        for file in &rule.files {
            let path = Path::new(file);
            if !path.is_absolute()
                || file.chars().any(char::is_control)
                || path.components().any(|c| {
                    matches!(
                        c,
                        std::path::Component::ParentDir | std::path::Component::CurDir
                    )
                })
            {
                return Err(SecretsError::ConfigInvalid(
                    "File rules require normalized absolute paths".into(),
                ));
            }
        }
    }
    Ok(())
}

pub fn file_allowed(policy: &AccessPolicy, reference: &SecretRef, file: &str) -> bool {
    policy
        .files
        .iter()
        .find(|r| r.item == reference.item && r.field == reference.field)
        .is_none_or(|r| r.files.contains(file))
}

pub fn grant_files(
    policy: &mut AccessPolicy,
    refs: &BTreeSet<SecretRef>,
    files: &BTreeSet<String>,
) {
    for r in refs {
        if let Some(rule) = policy
            .files
            .iter_mut()
            .find(|rule| rule.item == r.item && rule.field == r.field)
        {
            rule.files.extend(files.iter().cloned());
        } else {
            policy.files.push(FileRule {
                item: r.item.clone(),
                field: r.field.clone(),
                files: files.clone(),
            });
        }
    }
}

fn read_files<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<BTreeSet<String>, D::Error> {
    let values = Vec::<String>::deserialize(deserializer)?;
    let count = values.len();
    let files: BTreeSet<_> = values.into_iter().collect();
    if files.len() != count {
        return Err(serde::de::Error::custom("Duplicate file paths"));
    }
    Ok(files)
}
