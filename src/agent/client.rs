//! Agent client — communicates with the agent daemon over Unix socket.

use anyhow::Result;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use zeroize::Zeroize;

use crate::agent::server::{AgentRequest, AgentResponse};
use crate::crypto::keys::Vkek;

pub fn is_agent_running() -> bool {
    is_agent_running_for_vault(None)
}

pub fn is_agent_running_for_vault(vault_id: Option<&str>) -> bool {
    let sock_path = super::server::socket_path_for_vault(vault_id);
    if !sock_path.exists() {
        return false;
    }
    send_request_to(
        &AgentRequest::Ping {
            vault_id: vault_id.map(|s| s.to_string()),
        },
        vault_id,
    )
    .is_ok()
}

#[allow(dead_code)]
pub fn get_vkek() -> Result<Vkek> {
    get_vkek_for_vault(None)
}

pub fn get_vkek_for_vault(vault_id: Option<&str>) -> Result<Vkek> {
    let response = send_request_to(
        &AgentRequest::GetVkek {
            vault_id: vault_id.map(|s| s.to_string()),
        },
        vault_id,
    )?;
    if !response.ok {
        anyhow::bail!(
            "{}",
            response
                .message
                .unwrap_or_else(|| "vault is locked".to_string())
        );
    }

    let mut hex_str = response
        .vkek_hex
        .ok_or_else(|| anyhow::anyhow!("agent returned no VKEK"))?;
    let mut bytes = hex::decode(&hex_str).map_err(|_| anyhow::anyhow!("invalid VKEK hex"))?;
    hex_str.zeroize();

    if bytes.len() != 32 {
        bytes.zeroize();
        anyhow::bail!("invalid VKEK length from agent");
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    bytes.zeroize();
    let vkek = Vkek::from_bytes(key);
    key.zeroize();
    Ok(vkek)
}

#[allow(dead_code)]
pub fn store_vkek(vkek: &Vkek) -> Result<()> {
    store_vkek_for_vault(vkek, None)
}

pub fn store_vkek_for_vault(vkek: &Vkek, vault_id: Option<&str>) -> Result<()> {
    let mut hex_str = hex::encode(vkek.as_bytes());
    let response = send_request_to(
        &AgentRequest::StoreVkek {
            vkek_hex: hex_str.clone(),
            vault_id: vault_id.map(|s| s.to_string()),
        },
        vault_id,
    )?;
    hex_str.zeroize();

    if !response.ok {
        anyhow::bail!(
            "{}",
            response
                .message
                .unwrap_or_else(|| "failed to store VKEK".to_string())
        );
    }
    Ok(())
}

#[allow(dead_code)]
pub fn lock() -> Result<()> {
    lock_for_vault(None)
}

pub fn lock_for_vault(vault_id: Option<&str>) -> Result<()> {
    let response = send_request_to(
        &AgentRequest::Lock {
            vault_id: vault_id.map(|s| s.to_string()),
        },
        vault_id,
    )?;
    if !response.ok {
        anyhow::bail!(
            "{}",
            response
                .message
                .unwrap_or_else(|| "lock failed".to_string())
        );
    }
    Ok(())
}

#[allow(dead_code)]
pub fn shutdown() -> Result<()> {
    shutdown_for_vault(None)
}

#[allow(dead_code)]
pub fn shutdown_for_vault(vault_id: Option<&str>) -> Result<()> {
    send_request_to(
        &AgentRequest::Shutdown {
            vault_id: vault_id.map(|s| s.to_string()),
        },
        vault_id,
    )
    .ok();
    Ok(())
}

#[allow(dead_code)]
pub fn status() -> Result<AgentResponse> {
    status_for_vault(None)
}

pub fn status_for_vault(vault_id: Option<&str>) -> Result<AgentResponse> {
    send_request_to(
        &AgentRequest::Status {
            vault_id: vault_id.map(|s| s.to_string()),
        },
        vault_id,
    )
}

fn send_request_to(request: &AgentRequest, vault_id: Option<&str>) -> Result<AgentResponse> {
    let sock_path = super::server::socket_path_for_vault(vault_id);
    let stream = UnixStream::connect(&sock_path).map_err(|e| {
        anyhow::anyhow!(
            "failed to connect to agent at {}: {}",
            sock_path.display(),
            e
        )
    })?;

    stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;

    let mut writer = &stream;
    let mut request_json = serde_json::to_string(request)?;
    request_json.push('\n');
    writer.write_all(request_json.as_bytes())?;
    writer.flush()?;

    let reader = BufReader::new(&stream);
    for line in reader.lines() {
        let line = line?;
        if line.is_empty() {
            continue;
        }
        let response: AgentResponse = serde_json::from_str(&line)?;
        return Ok(response);
    }

    anyhow::bail!("no response from agent")
}
