use std::process::Command;

use serde::Deserialize;

use crate::errors::{Result, SecretsError};
use crate::providers::{ProviderItem, SecretProvider};

pub struct BitwardenProvider {
    session: Option<zeroize::Zeroizing<String>>,
}

impl BitwardenProvider {
    pub fn new() -> Self {
        Self { session: None }
    }

    pub fn with_session(session: String) -> Self {
        Self {
            session: Some(zeroize::Zeroizing::new(session)),
        }
    }

    fn run_bw(&self, args: &[&str]) -> Result<zeroize::Zeroizing<String>> {
        let mut cmd = Command::new("bw");
        cmd.args(args);

        // Add session if available
        if let Some(session) = &self.session {
            cmd.env("BW_SESSION", session.as_str());
        } else {
            return Err(SecretsError::BitwardenSessionExpired);
        }

        let mut output = crate::preflight::output(&mut cmd, std::time::Duration::from_secs(30)).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                SecretsError::BitwardenNotInstalled
            } else {
                SecretsError::BitwardenLoginFailed(e.to_string())
            }
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).replace(self.session.as_deref().map(|s| s.as_str()).unwrap_or("[none]"), "[REDACTED]");
            use zeroize::Zeroize;
            output.stdout.zeroize();
            output.stderr.zeroize();
            if stderr.contains("not logged in") || stderr.contains("Session key") {
                return Err(SecretsError::BitwardenSessionExpired);
            }
            return Err(SecretsError::BitwardenLoginFailed(stderr.to_string()));
        }

        let text = zeroize::Zeroizing::new(String::from_utf8_lossy(&output.stdout).to_string());
        use zeroize::Zeroize;
        output.stdout.zeroize();
        output.stderr.zeroize();
        Ok(text)
    }
}

impl Default for BitwardenProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretProvider for BitwardenProvider {
    fn name(&self) -> &str {
        "bitwarden"
    }

    fn is_available(&self) -> bool {
        Command::new("bw")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn sync(&self) -> Result<Vec<ProviderItem>> {
        let output = self.run_bw(&["list", "items"])?;

        let items: Vec<BwItem> = serde_json::from_str(&output)
            .map_err(|_| SecretsError::BitwardenLoginFailed("Invalid JSON from bw".into()))?;

        Ok(items.into_iter().map(|i| i.into()).collect())
    }

    fn get_item(&self, name: &str) -> Result<Option<ProviderItem>> {
        // Use `bw list items --search` + exact name filter instead of `bw get item`
        // because `bw get item` does fuzzy search across name, URI, and notes,
        // causing "More than one result" when a login entry coexists with a secrets entry.
        let output = self.run_bw(&["list", "items", "--search", name])?;

        let items: Vec<BwItem> = serde_json::from_str(&output)
            .map_err(|_| SecretsError::BitwardenLoginFailed("Invalid JSON from bw".into()))?;

        let mut matching = items.into_iter().filter(|i| i.name == name);
        let found = matching.next();
        if matching.next().is_some() {
            return Err(SecretsError::BitwardenLoginFailed(format!("Multiple records named '{name}'; choose a unique name in Bitwarden")));
        }

        let found = found.map(ProviderItem::from);
        if let Some(item) = &found {
            let mut names = std::collections::HashSet::new();
            if item.fields.iter().any(|(name, _)| !names.insert(name)) {
                return Err(SecretsError::BitwardenLoginFailed("Duplicate field names in Bitwarden item".into()));
            }
        }
        Ok(found)
    }
}

// Bitwarden item structure (simplified)
#[derive(Debug, Deserialize)]
struct BwItem {
    #[allow(dead_code)]
    name: String,
    #[serde(default)]
    fields: Option<Vec<BwField>>,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    login: Option<BwLogin>,
}

#[derive(Debug, Deserialize)]
struct BwField {
    name: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct BwLogin {
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
}

impl From<BwItem> for ProviderItem {
    fn from(item: BwItem) -> Self {
        let mut fields = Vec::new();

        // Add explicit fields
        if let Some(bw_fields) = item.fields {
            for f in bw_fields {
                fields.push((f.name, f.value));
            }
        }

        // Add login fields if present
        if let Some(login) = item.login {
            if let Some(username) = login.username {
                fields.push(("username".to_string(), username));
            }
            if let Some(password) = login.password {
                fields.push(("password".to_string(), password));
            }
        }

        ProviderItem {
            name: item.name,
            fields,
            notes: item.notes,
        }
    }
}
