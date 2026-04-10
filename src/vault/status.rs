use anyhow::Result;
use rusqlite::Connection;

use std::path::Path;

use crate::store::sqlite;

/// Get vault status information.
pub fn vault_status(conn: &Connection, db_path: &Path) -> Result<VaultStatus> {
    let vault_id =
        sqlite::get_meta(conn, "vault_id")?.map(|v| String::from_utf8_lossy(&v).to_string());
    let schema_version =
        sqlite::get_meta(conn, "schema_version")?.map(|v| String::from_utf8_lossy(&v).to_string());
    let cipher_suite =
        sqlite::get_meta(conn, "cipher_suite")?.map(|v| String::from_utf8_lossy(&v).to_string());
    let created_at =
        sqlite::get_meta(conn, "created_at")?.map(|v| String::from_utf8_lossy(&v).to_string());
    let secret_count = sqlite::count_secrets(conn)?;
    let auth_slots = sqlite::get_all_auth_slots(conn)?;

    let agent_status = get_agent_status(vault_id.as_deref());

    Ok(VaultStatus {
        initialized: vault_id.is_some(),
        vault_id,
        schema_version,
        cipher_suite,
        created_at,
        secret_count,
        auth_slot_count: auth_slots.len(),
        auth_slot_types: auth_slots.iter().map(|s| s.kind.to_string()).collect(),
        agent_status,
        db_path: db_path.display().to_string(),
    })
}

#[cfg(unix)]
fn get_agent_status(vault_id: Option<&str>) -> AgentStatus {
    let agent_running = crate::agent::client::is_agent_running_for_vault(vault_id);
    if agent_running {
        match crate::agent::client::status_for_vault(vault_id) {
            Ok(resp) => {
                if resp.locked == Some(true) {
                    AgentStatus::Locked
                } else {
                    AgentStatus::Unlocked {
                        ttl_remaining: resp.ttl_remaining_secs,
                    }
                }
            }
            Err(_) => AgentStatus::NotRunning,
        }
    } else {
        AgentStatus::NotRunning
    }
}

#[cfg(not(unix))]
fn get_agent_status(_vault_id: Option<&str>) -> AgentStatus {
    AgentStatus::NotRunning
}

#[derive(Debug)]
pub struct VaultStatus {
    pub initialized: bool,
    pub vault_id: Option<String>,
    pub schema_version: Option<String>,
    pub cipher_suite: Option<String>,
    pub created_at: Option<String>,
    pub secret_count: i64,
    pub auth_slot_count: usize,
    pub auth_slot_types: Vec<String>,
    pub agent_status: AgentStatus,
    pub db_path: String,
}

#[derive(Debug)]
pub enum AgentStatus {
    NotRunning,
    Locked,
    Unlocked { ttl_remaining: Option<u64> },
}
