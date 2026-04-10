//! Auth slot management.

use anyhow::Result;
use rusqlite::Connection;
use zeroize::Zeroizing;

use crate::crypto::keys::Vkek;
use crate::store::sqlite;

/// Create a passphrase auth slot.
pub fn create_passphrase_slot(conn: &Connection, vkek: &Vkek, passphrase: &[u8]) -> Result<i64> {
    let (derived_key_arr, salt) = crate::crypto::argon2::derive_key(passphrase)?;
    let derived_key = Zeroizing::new(derived_key_arr.to_vec());
    let derived_key_arr: [u8; 32] = derived_key
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid derived key length"))?;
    let (wrapped_vkek, nonce) = vkek.wrap(&derived_key_arr)?;

    let mut blob = wrapped_vkek;
    blob.extend_from_slice(&nonce);

    let slot_id = sqlite::insert_auth_slot(
        conn,
        sqlite::SlotKind::Passphrase,
        &blob,
        Some(&salt),
        Some(&crate::crypto::argon2::params_json()),
    )?;

    Ok(slot_id)
}

/// Parse Argon2 params from the slot's JSON `params` field.
/// Falls back to current defaults if params are missing or unparseable (pre-migration slots).
fn parse_argon2_params(slot: &sqlite::AuthSlotRow) -> (u32, u32, u32) {
    if let Some(ref json_str) = slot.params {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(json_str) {
            let time = v["time_cost"].as_u64().map(|n| n as u32);
            let mem = v["memory_cost"].as_u64().map(|n| n as u32);
            let par = v["parallelism"].as_u64().map(|n| n as u32);
            if let (Some(t), Some(m), Some(p)) = (time, mem, par) {
                return (t, m, p);
            }
        }
    }
    // Fallback to current defaults for pre-migration slots
    (
        crate::crypto::argon2::TIME_COST,
        crate::crypto::argon2::MEMORY_COST,
        crate::crypto::argon2::PARALLELISM,
    )
}

/// Unwrap VKEK from a passphrase auth slot.
pub fn unwrap_passphrase_slot(slot: &sqlite::AuthSlotRow, passphrase: &[u8]) -> Result<Vkek> {
    let salt = slot
        .salt
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("passphrase slot missing salt"))?;

    let (time_cost, memory_cost, parallelism) = parse_argon2_params(slot);
    let derived_key_arr =
        crate::crypto::argon2::derive_key_with_params(passphrase, salt, time_cost, memory_cost, parallelism)?;
    let derived_key = Zeroizing::new(derived_key_arr.to_vec());
    let derived_key_arr: [u8; 32] = derived_key
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid derived key length"))?;

    let blob = &slot.wrapped_vkek;
    if blob.len() < 12 {
        anyhow::bail!("invalid wrapped VKEK blob");
    }
    let (wrapped, nonce_bytes) = blob.split_at(blob.len() - 12);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(nonce_bytes);

    Vkek::unwrap(&derived_key_arr, wrapped, &nonce)
}

/// Create a trust-local auth slot (VKEK stored in kernel keyring).
#[cfg(target_os = "linux")]
pub fn create_trust_local_slot(conn: &Connection, vkek: &Vkek, vault_id: &str) -> Result<i64> {
    let machine_key = crate::auth::trustlocal::get_or_create_machine_key()?;
    let (wrapped_vkek, nonce) = vkek.wrap(&machine_key)?;

    let mut blob = wrapped_vkek;
    blob.extend_from_slice(&nonce);

    let slot_id = sqlite::insert_auth_slot(
        conn,
        sqlite::SlotKind::TrustLocal,
        &blob,
        None,
        Some(r#"{"method":"machine-key"}"#),
    )?;

    crate::auth::trustlocal::store_in_keyring(vkek, vault_id)?;
    Ok(slot_id)
}

#[cfg(target_os = "linux")]
pub fn create_tpm_slot(conn: &Connection, vkek: &Vkek) -> Result<i64> {
    crate::auth::tpm::create_tpm_slot(conn, vkek)
}

#[cfg(target_os = "linux")]
pub fn unwrap_tpm_slot(slot: &sqlite::AuthSlotRow) -> Result<Vkek> {
    crate::auth::tpm::unwrap_tpm_slot(slot)
}

#[cfg(target_os = "macos")]
pub fn create_keychain_slot(conn: &Connection, vkek: &Vkek) -> Result<i64> {
    crate::auth::keychain::create_keychain_slot(conn, vkek)
}

#[cfg(target_os = "macos")]
pub fn unwrap_keychain_slot(slot: &sqlite::AuthSlotRow) -> Result<Vkek> {
    crate::auth::keychain::unwrap_keychain_slot(slot)
}

#[cfg(target_os = "windows")]
pub fn create_dpapi_slot(conn: &Connection, vkek: &Vkek) -> Result<i64> {
    crate::auth::dpapi::create_dpapi_slot(conn, vkek)
}

#[cfg(target_os = "windows")]
pub fn unwrap_dpapi_slot(slot: &sqlite::AuthSlotRow) -> Result<Vkek> {
    crate::auth::dpapi::unwrap_dpapi_slot(slot)
}

/// Unwrap VKEK from a trust-local slot.
#[cfg(target_os = "linux")]
pub fn unwrap_trust_local_slot(slot: &sqlite::AuthSlotRow, vault_id: &str) -> Result<Vkek> {
    if let Ok(vkek) = crate::auth::trustlocal::load_from_keyring(vault_id) {
        return Ok(vkek);
    }

    let machine_key = crate::auth::trustlocal::get_or_create_machine_key()?;
    let blob = &slot.wrapped_vkek;
    if blob.len() < 12 {
        anyhow::bail!("invalid wrapped VKEK blob");
    }
    let (wrapped, nonce_bytes) = blob.split_at(blob.len() - 12);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(nonce_bytes);

    let vkek = Vkek::unwrap(&machine_key, wrapped, &nonce)?;
    crate::auth::trustlocal::store_in_keyring(&vkek, vault_id).ok();
    Ok(vkek)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::sqlite;

    fn setup_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        sqlite::init_schema(&conn).unwrap();
        conn
    }

    #[test]
    fn passphrase_slot_uses_stored_argon2_params() {
        let conn = setup_db();
        let vkek = Vkek::generate();
        let passphrase = b"test-passphrase";

        // Create a slot with non-default params (lower cost for speed in tests).
        let (derived_key_arr, salt) =
            crate::crypto::argon2::derive_key(passphrase).unwrap();
        let (wrapped_vkek, nonce) = vkek.wrap(&derived_key_arr).unwrap();

        let mut blob = wrapped_vkek;
        blob.extend_from_slice(&nonce);

        // Store with specific (non-default) Argon2 params.
        // We use the *current* defaults here because that's what derive_key uses.
        let custom_params = serde_json::json!({
            "algorithm": "argon2id",
            "version": "0x13",
            "time_cost": crate::crypto::argon2::TIME_COST,
            "memory_cost": crate::crypto::argon2::MEMORY_COST,
            "parallelism": crate::crypto::argon2::PARALLELISM,
            "output_len": 32,
        })
        .to_string();

        let slot_id = sqlite::insert_auth_slot(
            &conn,
            sqlite::SlotKind::Passphrase,
            &blob,
            Some(&salt),
            Some(&custom_params),
        )
        .unwrap();

        // Retrieve the slot and verify unwrap works.
        let slots = sqlite::get_auth_slots(&conn, sqlite::SlotKind::Passphrase).unwrap();
        let slot = slots.iter().find(|s| s.id == slot_id).unwrap();
        let unwrapped = unwrap_passphrase_slot(slot, passphrase).unwrap();
        assert_eq!(vkek.as_bytes(), unwrapped.as_bytes());
    }

    #[test]
    fn passphrase_slot_falls_back_to_defaults_when_params_missing() {
        let conn = setup_db();
        let vkek = Vkek::generate();
        let passphrase = b"fallback-test";

        // Derive with default params but store NO params JSON (simulates pre-migration slot).
        let (derived_key_arr, salt) =
            crate::crypto::argon2::derive_key(passphrase).unwrap();
        let (wrapped_vkek, nonce) = vkek.wrap(&derived_key_arr).unwrap();

        let mut blob = wrapped_vkek;
        blob.extend_from_slice(&nonce);

        let slot_id = sqlite::insert_auth_slot(
            &conn,
            sqlite::SlotKind::Passphrase,
            &blob,
            Some(&salt),
            None, // no params — pre-migration
        )
        .unwrap();

        let slots = sqlite::get_auth_slots(&conn, sqlite::SlotKind::Passphrase).unwrap();
        let slot = slots.iter().find(|s| s.id == slot_id).unwrap();
        assert!(slot.params.is_none());

        // Should still unwrap using defaults.
        let unwrapped = unwrap_passphrase_slot(slot, passphrase).unwrap();
        assert_eq!(vkek.as_bytes(), unwrapped.as_bytes());
    }

    #[test]
    fn passphrase_slot_respects_explicit_params_not_defaults() {
        // Create a slot with specific low-cost params, then verify that
        // unwrap uses those stored params (not the module defaults).
        let conn = setup_db();
        let vkek = Vkek::generate();
        let passphrase = b"explicit-params";

        // Use intentionally different params than the module defaults.
        let custom_time: u32 = 1;
        let custom_mem: u32 = 16384; // 16 MiB
        let custom_par: u32 = 2;

        let mut salt = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut salt);

        let derived = crate::crypto::argon2::derive_key_with_params(
            passphrase,
            &salt,
            custom_time,
            custom_mem,
            custom_par,
        )
        .unwrap();

        let (wrapped_vkek, nonce) = vkek.wrap(&derived).unwrap();
        let mut blob = wrapped_vkek;
        blob.extend_from_slice(&nonce);

        let params_json = serde_json::json!({
            "algorithm": "argon2id",
            "time_cost": custom_time,
            "memory_cost": custom_mem,
            "parallelism": custom_par,
            "output_len": 32,
        })
        .to_string();

        let slot_id = sqlite::insert_auth_slot(
            &conn,
            sqlite::SlotKind::Passphrase,
            &blob,
            Some(&salt),
            Some(&params_json),
        )
        .unwrap();

        let slots = sqlite::get_auth_slots(&conn, sqlite::SlotKind::Passphrase).unwrap();
        let slot = slots.iter().find(|s| s.id == slot_id).unwrap();

        // Unwrap must succeed with the stored custom params.
        let unwrapped = unwrap_passphrase_slot(slot, passphrase).unwrap();
        assert_eq!(vkek.as_bytes(), unwrapped.as_bytes());

        // If we had used default params (which are different), it would fail.
        // Verify this by deriving with defaults and confirming mismatch.
        let default_derived = crate::crypto::argon2::derive_key_with_salt(passphrase, &salt).unwrap();
        assert_ne!(derived, default_derived, "custom params should differ from defaults");
    }
}
