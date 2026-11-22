//! Serializes read-modify-write and migration; the OS releases the lock on exit.
use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::time::{Duration, Instant};
use crate::{config::Config, errors::{Result, SecretsError}};

pub fn acquire() -> Result<File> {
    let directory = Config::secrets_dir();
    std::fs::create_dir_all(&directory)?;
    let file = OpenOptions::new().create(true).read(true).write(true).mode(0o600).open(directory.join(".command.lock"))?;
    let start = Instant::now();
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(std::fs::TryLockError::WouldBlock) if start.elapsed() < Duration::from_secs(20) => std::thread::sleep(Duration::from_millis(50)),
            Err(error) => return Err(SecretsError::ConfigInvalid(format!("Another secrets command is active or lock unavailable: {error}"))),
        }
    }
}
