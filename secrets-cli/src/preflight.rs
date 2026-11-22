//! One Bitwarden refresh per CLI invocation, before dispatch and authentication.
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::io::Read;
use crate::config::Config;
use crate::errors::{Result, SecretsError};

pub fn output(command: &mut Command, timeout: Duration) -> std::io::Result<std::process::Output> {
    let mut child = command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let errors = tx.clone();
    std::thread::spawn(move || { let mut bytes = Vec::new(); let result = stdout.take(16 * 1024 * 1024).read_to_end(&mut bytes).map(|_| bytes); let _ = tx.send((false, result)); });
    std::thread::spawn(move || { let mut bytes = Vec::new(); let result = stderr.take(64 * 1024).read_to_end(&mut bytes).map(|_| bytes); let _ = errors.send((true, result)); });
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? { break status; }
        if start.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "bw timed out"));
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    // Child descendants can retain a pipe after the main process exits.
    // Bound reads too: never join a reader indefinitely.
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    for _ in 0..2 {
        let (is_error, data) = rx.recv_timeout(timeout.saturating_sub(start.elapsed()))
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "bw output timed out"))?;
        if is_error { stderr = data?; } else { stdout = data?; }
    }
    Ok(std::process::Output { status, stdout, stderr })
}

pub fn refresh() -> Result<()> {
    let config = Config::load().ok();
    if config.as_ref().is_some_and(|c| c.provider != "bitwarden") { return Ok(()); }
    let mut command = Command::new("bw");
    command.arg("sync").env_remove("BW_SESSION").env_remove("BW_PASSWORD");
    let result = output(&mut command, Duration::from_secs(20));
    let result = match result {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => Err(SecretsError::BitwardenLoginFailed(format!("bw sync: {}", String::from_utf8_lossy(&o.stderr).trim()))),
        Err(e) => Err(SecretsError::BitwardenLoginFailed(format!("bw sync: {e}"))),
    };
    // Metadata only; never save bw stdout or credentials.
    let path = Config::secrets_dir().join("sync-status.json");
    if Config::secrets_dir().is_dir() {
        let mut status: serde_json::Value = std::fs::read(&path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_else(|| serde_json::json!({}));
        match &result {
            Ok(()) => { status["last_success"] = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs().into(); status["failed"] = false.into(); }
            Err(_) => { status["failed"] = true.into(); }
        }
        // No raw provider error retained on disk.
        let _ = crate::vault::atomic_write(&path, status.to_string().as_bytes());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inherited_pipe_does_not_defeat_timeout() {
        let start = Instant::now();
        let result = output(Command::new("/bin/sh").args(["-c", "sleep 2 & exit 0"]), Duration::from_millis(150));
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
        assert!(start.elapsed() < Duration::from_secs(1));
    }
}
