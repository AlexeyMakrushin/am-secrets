use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Command;
use std::thread;
use std::time::Duration;

use crate::daemon::protocol::{Request, Response};
use crate::errors::{Result, SecretsError};
use crate::security::SecretKey;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use zeroize::Zeroizing;

pub struct MemoryState {
    pub master_key: SecretKey,
    pub session: Zeroizing<String>,
}

const READ_TIMEOUT: Duration = Duration::from_secs(10);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RESPONSE_SIZE: usize = 65536;
const AUTO_START_WAIT_MS: u64 = 100;
const AUTO_START_MAX_ATTEMPTS: u32 = 50; // 5 seconds total

pub struct DaemonClient {
    socket_path: String,
    auto_start: bool,
}

impl DaemonClient {
    pub fn new(socket_path: String) -> Self {
        Self {
            socket_path,
            auto_start: true, // Default to auto-start enabled
        }
    }

    pub fn with_auto_start(socket_path: String, auto_start: bool) -> Self {
        Self { socket_path, auto_start }
    }

    pub fn default_socket_path() -> String {
        crate::config::Config::secrets_dir().join("daemon.sock").to_string_lossy().into()

    }

    /// Try to start daemon via launchctl if not running
    fn try_start_daemon(&self) -> bool {
        eprintln!("Daemon not running, attempting to start...");

        // Try launchctl start first
        let result = Command::new("launchctl")
            .args(["start", "com.ai-secrets.daemon"])
            .output();

        if result.is_err() {
            // launchctl start failed, try load
            let _ = Command::new("launchctl")
                .args(["load", "-w"])
                .arg(format!("{}/Library/LaunchAgents/com.ai-secrets.daemon.plist",
                    dirs::home_dir().map(|h| h.to_string_lossy().to_string()).unwrap_or_default()))
                .output();
        }

        // Wait for socket to appear
        let path = Path::new(&self.socket_path);
        for _ in 0..AUTO_START_MAX_ATTEMPTS {
            if path.exists() {
                eprintln!("Daemon started successfully.");
                return true;
            }
            thread::sleep(Duration::from_millis(AUTO_START_WAIT_MS));
        }

        eprintln!("Failed to start daemon within timeout.");
        false
    }

    fn connect(&self) -> Result<UnixStream> {
        let path = Path::new(&self.socket_path);

        // Check if socket exists, try auto-start if enabled
        if !path.exists() {
            if self.auto_start {
                if !self.try_start_daemon() {
                    return Err(SecretsError::DaemonNotRunning);
                }
            } else {
                return Err(SecretsError::DaemonNotRunning);
            }
        }

        // Try to connect
        match UnixStream::connect(path) {
            Ok(stream) => {
                stream
                    .set_read_timeout(Some(READ_TIMEOUT))
                    .map_err(SecretsError::DaemonConnectionFailed)?;
                stream
                    .set_write_timeout(Some(WRITE_TIMEOUT))
                    .map_err(SecretsError::DaemonConnectionFailed)?;
                Ok(stream)
            }
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused && self.auto_start => {
                // Stale socket - daemon crashed, try to restart
                eprintln!("Stale socket detected, removing and restarting daemon...");
                let _ = std::fs::remove_file(path);

                if self.try_start_daemon() {
                    // Retry connection after restart
                    let stream = UnixStream::connect(path)
                        .map_err(|_| SecretsError::DaemonNotRunning)?;
                    stream
                        .set_read_timeout(Some(READ_TIMEOUT))
                        .map_err(SecretsError::DaemonConnectionFailed)?;
                    stream
                        .set_write_timeout(Some(WRITE_TIMEOUT))
                        .map_err(SecretsError::DaemonConnectionFailed)?;
                    Ok(stream)
                } else {
                    Err(SecretsError::DaemonNotRunning)
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                Err(SecretsError::DaemonNotRunning)
            }
            Err(e) => Err(SecretsError::DaemonConnectionFailed(e)),
        }
    }

    fn send_request(&self, request: &Request) -> Result<Response> {
        let mut stream = self.connect()?;

        // Serialize request to JSON
        let json = Zeroizing::new(serde_json::to_vec(request)
            .map_err(|e| SecretsError::InvalidResponse(e.to_string()))?);

        // Send with length-prefix framing: [4 bytes: big-endian length][JSON]
        let length = json.len() as u32;
        let header = [
            ((length >> 24) & 0xFF) as u8,
            ((length >> 16) & 0xFF) as u8,
            ((length >> 8) & 0xFF) as u8,
            (length & 0xFF) as u8,
        ];

        stream
            .write_all(&header)
            .map_err(SecretsError::DaemonConnectionFailed)?;
        stream
            .write_all(&json)
            .map_err(SecretsError::DaemonConnectionFailed)?;
        stream
            .flush()
            .map_err(SecretsError::DaemonConnectionFailed)?;

        // Shutdown write side to signal end of request
        stream
            .shutdown(std::net::Shutdown::Write)
            .map_err(SecretsError::DaemonConnectionFailed)?;

        // Read response with length-prefix framing
        let mut header_buf = [0u8; 4];
        stream
            .read_exact(&mut header_buf)
            .map_err(SecretsError::DaemonConnectionFailed)?;

        let resp_length = u32::from_be_bytes(header_buf) as usize;
        if resp_length == 0 || resp_length > MAX_RESPONSE_SIZE {
            return Err(SecretsError::InvalidResponse(format!(
                "Invalid response length: {}",
                resp_length
            )));
        }

        let mut buffer = Zeroizing::new(vec![0u8; resp_length]);
        stream
            .read_exact(&mut buffer)
            .map_err(SecretsError::DaemonConnectionFailed)?;

        // Parse response
        let response: Response = serde_json::from_slice(&buffer)
            .map_err(|e| SecretsError::InvalidResponse(e.to_string()))?;

        // SECURITY: Zeroize buffer that may contain PIN
        if response.v != Some(crate::daemon::protocol::PROTOCOL_VERSION) {
            return Err(SecretsError::InvalidResponse("Daemon protocol mismatch. Install matching CLI and daemon; old PIN daemon is not supported.".into()));
        }

        Ok(response)
    }

    pub fn ping(&self) -> Result<bool> {
        Ok(self.send_request(&Request::new("PING", None))?.status == "alive")
    }

    fn checked(&self, request: &Request) -> Result<Response> {
        let response = self.send_request(request)?;
        if response.status == "ok" { return Ok(response); }
        Err(match response.code.as_deref() {
            Some("UNAUTHORIZED") => SecretsError::DaemonUnauthorized,
            Some("SESSION_EXPIRED") => SecretsError::SessionExpired,
            Some("RATE_LIMITED") => SecretsError::DaemonRateLimited("Too many requests".into()),
            _ => SecretsError::InvalidResponse(response.message.clone().unwrap_or_else(|| "Daemon error".into())),
        })
    }

    pub fn get_state(&self, context: &str) -> Result<MemoryState> {
        let response = self.checked(&Request::new("GET_STATE", Some(context.into())))?;
        let raw = Zeroizing::new(BASE64.decode(response.master_key.as_deref().unwrap_or(""))
            .map_err(|_| SecretsError::InvalidResponse("Invalid key encoding".into()))?);
        let master_key = SecretKey::from_slice(&raw)
            .ok_or_else(|| SecretsError::InvalidResponse("Invalid key size".into()))?;
        Ok(MemoryState { master_key, session: Zeroizing::new(response.provider_session.clone().unwrap_or_default()) })
    }

    pub fn set_state(&self, context: &str, key: &SecretKey, session: &str) -> Result<()> {
        let mut request = Request::new("SET_STATE", Some(context.into()));
        request.master_key = Some(BASE64.encode(key.expose()));
        if !session.is_empty() { request.provider_session = Some(session.into()); }
        self.checked(&request).map(|_| ())
    }

    pub fn clear_state(&self) -> Result<()> {
        self.checked(&Request::new("CLEAR_STATE", None)).map(|_| ())
    }

    pub fn check_session(&self, context: &str) -> Result<bool> {
        Ok(self.checked(&Request::new("CHECK_SESSION", Some(context.into())))?.session_active.unwrap_or(false))
    }

    pub fn retire_legacy_pin(&self) -> Result<()> {
        self.checked(&Request::new("RETIRE_LEGACY_PIN", None)).map(|_| ())
    }
}
