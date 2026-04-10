//! Unix socket agent server — holds unlocked VKEK in memory.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zeroize::Zeroize;

use crate::crypto::keys::Vkek;

/// Default TTL for the agent session (15 minutes).
const DEFAULT_TTL_SECS: u64 = 15 * 60;
/// Maximum absolute lifetime for an agent session (4 hours).
const MAX_LIFETIME_SECS: u64 = 4 * 60 * 60;

/// Agent request types.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "command")]
pub enum AgentRequest {
    #[serde(rename = "get_vkek")]
    GetVkek {
        #[serde(default)]
        vault_id: Option<String>,
    },
    #[serde(rename = "store_vkek")]
    StoreVkek {
        vkek_hex: String,
        #[serde(default)]
        vault_id: Option<String>,
    },
    #[serde(rename = "lock")]
    Lock {
        #[serde(default)]
        vault_id: Option<String>,
    },
    #[serde(rename = "status")]
    Status {
        #[serde(default)]
        vault_id: Option<String>,
    },
    #[serde(rename = "ping")]
    Ping {
        #[serde(default)]
        vault_id: Option<String>,
    },
    #[serde(rename = "shutdown")]
    Shutdown {
        #[serde(default)]
        vault_id: Option<String>,
    },
}

/// Agent response types.
#[derive(Debug, Serialize, Deserialize)]
pub struct AgentResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vkek_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locked: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_remaining_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault_id: Option<String>,
}

struct AgentState {
    vkek: Option<Vkek>,
    vault_id: Option<String>,
    last_access: Instant,
    created_at: Instant,
    ttl: Duration,
    max_lifetime: Duration,
    terminate: bool,
}

impl Drop for AgentState {
    fn drop(&mut self) {
        self.vkek.take();
    }
}

#[allow(dead_code)]
pub fn socket_path() -> PathBuf {
    socket_path_for_vault(None)
}

/// Socket path namespaced by vault_id hash (first 8 chars of SHA256).
pub fn socket_path_for_vault(vault_id: Option<&str>) -> PathBuf {
    let sock_name = if let Some(vid) = vault_id {
        use sha2::Digest;
        let hash = sha2::Sha256::digest(vid.as_bytes());
        let prefix = hex::encode(&hash[..4]);
        format!("agent-{}.sock", prefix)
    } else {
        "agent.sock".to_string()
    };

    if let Ok(runtime) = std::env::var("XDG_RUNTIME_DIR") {
        PathBuf::from(runtime).join("vault").join(sock_name)
    } else {
        PathBuf::from("/tmp")
            .join(format!("vault-agent-{}", nix::unistd::getuid().as_raw()))
            .join(sock_name)
    }
}

pub fn run_agent(
    vkek: Option<Vkek>,
    ttl_secs: Option<u64>,
    vault_id: Option<String>,
) -> Result<()> {
    crate::agent::memory::harden_process()?;

    let sock_path = socket_path_for_vault(vault_id.as_deref());
    if let Some(parent) = sock_path.parent() {
        std::fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
    }

    let _ = std::fs::remove_file(&sock_path);
    let listener = UnixListener::bind(&sock_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&sock_path, std::fs::Permissions::from_mode(0o600))?;
    }

    let ttl = Duration::from_secs(ttl_secs.unwrap_or(DEFAULT_TTL_SECS));
    let now = Instant::now();
    let state = Arc::new(Mutex::new(AgentState {
        vkek,
        vault_id,
        last_access: now,
        created_at: now,
        ttl,
        max_lifetime: Duration::from_secs(MAX_LIFETIME_SECS),
        terminate: false,
    }));

    eprintln!("vault agent: listening on {}", sock_path.display());
    eprintln!("vault agent: TTL = {} seconds", ttl.as_secs());

    // Cooperative shutdown signal shared between watchdog and main loop.
    let shutdown = Arc::new(AtomicBool::new(false));

    let state_clone = Arc::clone(&state);
    let shutdown_wd = Arc::clone(&shutdown);
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(5));
        let guard = match state_clone.lock() {
            Ok(g) => g,
            Err(_poisoned) => {
                eprintln!("vault agent: watchdog: mutex poisoned, forcing shutdown");
                shutdown_wd.store(true, Ordering::SeqCst);
                return;
            }
        };
        let idle_expired = guard.vkek.is_some() && guard.last_access.elapsed() > guard.ttl;
        let lifetime_expired = guard.created_at.elapsed() > guard.max_lifetime;
        if idle_expired || lifetime_expired {
            drop(guard);
            let mut guard = match state_clone.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            guard.vkek.take();
            if lifetime_expired {
                eprintln!("vault agent: max lifetime expired, shutting down");
            } else {
                eprintln!("vault agent: TTL expired, shutting down");
            }
            shutdown_wd.store(true, Ordering::SeqCst);
            return;
        }
    });

    // Set a short accept timeout so the main loop can periodically check shutdown.
    // SO_RCVTIMEO applies to accept() on Linux.
    listener.set_nonblocking(false)?;
    let timeout = std::time::Duration::from_secs(2);
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let tv = libc::timeval {
            tv_sec: timeout.as_secs() as libc::time_t,
            tv_usec: 0,
        };
        unsafe {
            libc::setsockopt(
                listener.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &tv as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::timeval>() as libc::socklen_t,
            );
        }
    }

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(e) = handle_client(stream, &state) {
                    eprintln!("vault agent: client error: {}", e);
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => eprintln!("vault agent: accept error: {}", e),
        }

        // Check cooperative shutdown from watchdog or client-requested terminate.
        if shutdown.load(Ordering::SeqCst) {
            let _ = std::fs::remove_file(&sock_path);
            return Ok(());
        }

        let guard = match state.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                eprintln!("vault agent: mutex poisoned, recovering");
                poisoned.into_inner()
            }
        };
        if guard.terminate {
            drop(guard);
            let _ = std::fs::remove_file(&sock_path);
            return Ok(());
        }
    }

    let _ = std::fs::remove_file(&sock_path);
    Ok(())
}

fn request_vault_id(request: &AgentRequest) -> Option<&str> {
    match request {
        AgentRequest::GetVkek { vault_id }
        | AgentRequest::StoreVkek { vault_id, .. }
        | AgentRequest::Lock { vault_id }
        | AgentRequest::Status { vault_id }
        | AgentRequest::Ping { vault_id }
        | AgentRequest::Shutdown { vault_id } => vault_id.as_deref(),
    }
}

fn validate_scope(request: &AgentRequest, state: &AgentState) -> Result<()> {
    if let Some(stored) = state.vault_id.as_deref() {
        match request_vault_id(request) {
            Some(requested) if requested == stored => {} // match
            Some(requested) => {
                anyhow::bail!(
                    "vault_id mismatch — agent holds '{}' but request asks for '{}'",
                    stored,
                    requested
                );
            }
            None => {
                anyhow::bail!("request missing vault_id — agent is scoped to '{}'", stored);
            }
        }
    }
    Ok(())
}

fn response_template(state: &AgentState) -> AgentResponse {
    AgentResponse {
        ok: true,
        vkek_hex: None,
        message: None,
        locked: None,
        ttl_remaining_secs: None,
        vault_id: state.vault_id.clone(),
    }
}

fn handle_client(
    stream: std::os::unix::net::UnixStream,
    state: &Arc<Mutex<AgentState>>,
) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let cred =
            nix::sys::socket::getsockopt(&stream, nix::sys::socket::sockopt::PeerCredentials)?;
        let my_uid = nix::unistd::getuid();
        if cred.uid() != my_uid.as_raw() {
            anyhow::bail!(
                "peer UID {} does not match agent UID {}",
                cred.uid(),
                my_uid
            );
        }
    }

    let reader = BufReader::new(&stream);
    let mut writer = &stream;

    for line in reader.lines() {
        let line = line?;
        if line.is_empty() {
            continue;
        }
        let request: AgentRequest =
            serde_json::from_str(&line).map_err(|e| anyhow::anyhow!("invalid request: {}", e))?;
        let response = process_request(request, state)?;
        let mut resp_json = serde_json::to_string(&response)?;
        resp_json.push('\n');
        writer.write_all(resp_json.as_bytes())?;
        writer.flush()?;
        if response.message.as_deref() == Some("shutting down") {
            return Ok(());
        }
    }

    Ok(())
}

fn process_request(request: AgentRequest, state: &Arc<Mutex<AgentState>>) -> Result<AgentResponse> {
    let mut guard = state.lock().map_err(|_| anyhow::anyhow!("agent state mutex poisoned"))?;
    validate_scope(&request, &guard)?;

    match request {
        AgentRequest::Ping { .. } => {
            let mut resp = response_template(&guard);
            resp.message = Some("pong".to_string());
            Ok(resp)
        }
        AgentRequest::GetVkek { .. } => {
            if let Some(ref vkek) = guard.vkek {
                let mut hex_val = hex::encode(vkek.as_bytes());
                guard.last_access = Instant::now();
                let mut resp = response_template(&guard);
                resp.vkek_hex = Some(hex_val.clone());
                resp.locked = Some(false);
                resp.ttl_remaining_secs = Some(
                    guard
                        .ttl
                        .as_secs()
                        .saturating_sub(guard.last_access.elapsed().as_secs()),
                );
                hex_val.zeroize();
                Ok(resp)
            } else {
                let mut resp = response_template(&guard);
                resp.ok = false;
                resp.message = Some("vault is locked".to_string());
                resp.locked = Some(true);
                Ok(resp)
            }
        }
        AgentRequest::StoreVkek {
            mut vkek_hex,
            vault_id,
        } => {
            let mut bytes = hex::decode(&vkek_hex).map_err(|_| anyhow::anyhow!("invalid hex"))?;
            vkek_hex.zeroize();
            if bytes.len() != 32 {
                bytes.zeroize();
                anyhow::bail!("invalid VKEK length");
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            bytes.zeroize();
            guard.vkek = Some(Vkek::from_bytes(key));
            key.zeroize();
            if vault_id.is_some() {
                guard.vault_id = vault_id;
            }
            guard.last_access = Instant::now();
            let mut resp = response_template(&guard);
            resp.message = Some("VKEK stored".to_string());
            resp.locked = Some(false);
            resp.ttl_remaining_secs = Some(
                guard
                    .ttl
                    .as_secs()
                    .saturating_sub(guard.last_access.elapsed().as_secs()),
            );
            Ok(resp)
        }
        AgentRequest::Lock { .. } => {
            guard.vkek.take();
            guard.terminate = true;
            let mut resp = response_template(&guard);
            resp.message = Some("locked".to_string());
            resp.locked = Some(true);
            Ok(resp)
        }
        AgentRequest::Status { .. } => {
            let locked = guard.vkek.is_none();
            let ttl_remaining = if !locked {
                Some(
                    guard
                        .ttl
                        .as_secs()
                        .saturating_sub(guard.last_access.elapsed().as_secs()),
                )
            } else {
                None
            };
            let mut resp = response_template(&guard);
            resp.message = Some(if locked { "locked" } else { "unlocked" }.to_string());
            resp.locked = Some(locked);
            resp.ttl_remaining_secs = ttl_remaining;
            Ok(resp)
        }
        AgentRequest::Shutdown { .. } => {
            guard.vkek.take();
            guard.terminate = true;
            let mut resp = response_template(&guard);
            resp.message = Some("shutting down".to_string());
            resp.locked = Some(true);
            Ok(resp)
        }
    }
}
