use crate::{auth, config::Config, daemon::DaemonClient, errors::Result, vault::KeysFile};

pub fn status_command() -> Result<()> {
    println!("am-secrets v{}", env!("CARGO_PKG_VERSION"));
    let config = Config::load()?;
    println!("Provider: {}", config.provider);
    println!(
        "Vault: {}",
        if Config::vault_path().exists() {
            "present"
        } else {
            "missing"
        }
    );
    let client =
        DaemonClient::with_auto_start(config.socket_path().to_string_lossy().into(), false);
    match client.ping() {
        Ok(true) => {
            println!("Daemon: running (protocol 2)");
            if let Ok(keys) = KeysFile::load(&Config::keys_path()) {
                match client.check_session(&auth::context(&config, &keys)?) {
                    Ok(true) => println!("Session: unlocked, memory only"),
                    Ok(false) => println!("Session: locked; run secrets unlock"),
                    Err(error) => println!("Session: unavailable ({error})"),
                }
                println!(
                    "PIN migration: {}",
                    if keys.has_pin_wrap() {
                        "pending; run secrets unlock"
                    } else {
                        "complete"
                    }
                );
            }
        }
        Ok(false) => println!("Daemon: not responding"),
        Err(error) => println!("Daemon: unavailable ({error})"),
    }
    if let Ok(bytes) = std::fs::read(Config::secrets_dir().join("sync-status.json")) {
        if let Ok(status) = serde_json::from_slice::<serde_json::Value>(&bytes) {
            println!(
                "Last successful bw sync (Unix seconds): {}",
                status["last_success"]
            );
            println!(
                "Latest bw sync: {}",
                if status["failed"] == true {
                    "failed; see stderr"
                } else {
                    "successful"
                }
            );
        }
    }
    crate::background::show_status();
    Ok(())
}
