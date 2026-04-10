//! macOS Keychain auth backend.
//!
//! Stores the VKEK as a generic password in the user's login keychain
//! via `security-framework`.  macOS handles authentication automatically
//! (Touch ID / password prompt).

#![cfg(target_os = "macos")]

use anyhow::{Context, Result};
use zeroize::Zeroizing;

use crate::crypto::keys::Vkek;
use crate::store::sqlite;

const SERVICE_NAME: &str = "com.vault.vkek";

fn keychain_store(vault_id: &str, vkek: &Vkek) -> Result<()> {
    use security_framework::passwords::set_generic_password;
    set_generic_password(SERVICE_NAME, vault_id, vkek.as_bytes())
        .context("failed to store VKEK in macOS Keychain")?;
    Ok(())
}

fn keychain_load(vault_id: &str) -> Result<Vkek> {
    use security_framework::passwords::get_generic_password;

    let data = Zeroizing::new(
        get_generic_password(SERVICE_NAME, vault_id)
            .context("failed to retrieve VKEK from macOS Keychain")?,
    );

    if data.len() != 32 {
        anyhow::bail!(
            "keychain VKEK has invalid length ({}, expected 32)",
            data.len()
        );
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(data.as_slice());
    Ok(Vkek::from_bytes(key))
}

pub fn keychain_delete(vault_id: &str) -> Result<()> {
    use security_framework::passwords::delete_generic_password;
    delete_generic_password(SERVICE_NAME, vault_id)
        .context("failed to delete VKEK from macOS Keychain")?;
    Ok(())
}

pub fn create_keychain_slot(conn: &rusqlite::Connection, vkek: &Vkek) -> Result<i64> {
    let vault_id = sqlite::get_meta(conn, "vault_id")?
        .map(|v| String::from_utf8_lossy(&v).to_string())
        .unwrap_or_else(|| "default".to_string());

    keychain_store(&vault_id, vkek).context("failed to store VKEK in macOS Keychain")?;

    let marker = vault_id.as_bytes().to_vec();
    let slot_id = sqlite::insert_auth_slot(
        conn,
        sqlite::SlotKind::Keychain,
        &marker,
        None,
        Some(&format!(
            r#"{{"method":"macos-keychain","service":"{}","account":"{}"}}"#,
            SERVICE_NAME, vault_id
        )),
    )?;

    Ok(slot_id)
}

pub fn unwrap_keychain_slot(slot: &sqlite::AuthSlotRow) -> Result<Vkek> {
    let vault_id =
        String::from_utf8(slot.wrapped_vkek.clone()).context("invalid keychain slot data")?;
    keychain_load(&vault_id)
}

pub fn remove_keychain_slot(slot: &sqlite::AuthSlotRow) -> Result<()> {
    let vault_id =
        String::from_utf8(slot.wrapped_vkek.clone()).context("invalid keychain slot data")?;
    keychain_delete(&vault_id)
}
