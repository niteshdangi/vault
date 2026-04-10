use anyhow::Result;
use rusqlite::Connection;
use zeroize::Zeroizing;

use crate::crypto::keys::Vkek;
use crate::store::sqlite;

/// List all auth slots with their info.
pub fn list_auth_slots(conn: &Connection) -> Result<Vec<AuthSlotInfo>> {
    let slots = sqlite::get_all_auth_slots(conn)?;
    let mut result = Vec::with_capacity(slots.len());
    for slot in &slots {
        result.push(AuthSlotInfo {
            id: slot.id,
            slot_type: slot.kind.to_string(),
            created_at: slot
                .created_at
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
        });
    }
    Ok(result)
}

#[derive(Debug)]
pub struct AuthSlotInfo {
    pub id: i64,
    pub slot_type: String,
    pub created_at: String,
}

/// Add a new passphrase auth slot (requires existing VKEK).
pub fn add_passphrase_slot(conn: &Connection, vkek: &Vkek) -> Result<i64> {
    let passphrase = Zeroizing::new(crate::auth::passphrase::prompt_passphrase(true)?);
    crate::auth::slot::create_passphrase_slot(conn, vkek, passphrase.as_slice())
}

/// Add a new trust-local auth slot (requires existing VKEK, Linux only).
#[cfg(target_os = "linux")]
pub fn add_trust_local_slot(
    conn: &Connection,
    vkek: &Vkek,
    vault_id: &str,
    force: bool,
) -> Result<i64> {
    let slots = sqlite::get_all_auth_slots(conn)?;
    let has_passphrase = slots.iter().any(|s| s.kind == sqlite::SlotKind::Passphrase);
    if !has_passphrase {
        eprintln!("⚠ trust-local provides convenience, not security. A passphrase slot is required as primary auth.");
        if !force {
            anyhow::bail!("refusing to add trust-local without an existing passphrase slot; use --force only if you intentionally want convenience-only auth");
        }
    }
    crate::auth::slot::create_trust_local_slot(conn, vkek, vault_id)
}

/// Add a new TPM2 auth slot (requires existing VKEK, Linux only).
#[cfg(target_os = "linux")]
pub fn add_tpm_slot(conn: &Connection, vkek: &Vkek) -> Result<i64> {
    crate::auth::slot::create_tpm_slot(conn, vkek)
}

/// Add a new Keychain auth slot (requires existing VKEK, macOS only).
#[cfg(target_os = "macos")]
pub fn add_keychain_slot(conn: &Connection, vkek: &Vkek) -> Result<i64> {
    crate::auth::slot::create_keychain_slot(conn, vkek)
}

/// Add a new DPAPI auth slot (requires existing VKEK, Windows only).
#[cfg(target_os = "windows")]
pub fn add_dpapi_slot(conn: &Connection, vkek: &Vkek) -> Result<i64> {
    crate::auth::slot::create_dpapi_slot(conn, vkek)
}

/// Remove an auth slot by ID. Must have at least 1 remaining.
/// Dispatches best-effort backend cleanup before deleting the DB row.
pub fn remove_auth_slot(conn: &Connection, slot_id: i64) -> Result<()> {
    let count = sqlite::count_auth_slots(conn)?;
    if count <= 1 {
        anyhow::bail!("cannot remove the last auth slot — at least one must remain");
    }

    // Load the slot so we can dispatch backend cleanup.
    let slot = sqlite::get_auth_slot_by_id(conn, slot_id)?
        .ok_or_else(|| anyhow::anyhow!("auth slot {} not found", slot_id))?;

    // Best-effort backend cleanup based on slot kind.
    // Even if cleanup fails we still remove the DB row — the user explicitly wants it gone.
    match slot.kind {
        #[cfg(target_os = "linux")]
        sqlite::SlotKind::TrustLocal => {
            let vault_id = super::get_vault_id(conn).unwrap_or_default();
            if let Err(e) = crate::auth::trustlocal::clear_keyring(&vault_id) {
                eprintln!("⚠ failed to clean up keyring entry: {}", e);
            }
        }
        #[cfg(target_os = "macos")]
        sqlite::SlotKind::Keychain => {
            if let Err(e) = crate::auth::keychain::remove_keychain_slot(&slot) {
                eprintln!("⚠ failed to clean up Keychain entry: {}", e);
            }
        }
        // Passphrase / TPM / DPAPI: no external artifact to clean up
        _ => {}
    }

    if !sqlite::delete_auth_slot(conn, slot_id)? {
        anyhow::bail!("auth slot {} not found", slot_id);
    }

    Ok(())
}
