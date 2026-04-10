use anyhow::Result;
use rusqlite::Connection;
use zeroize::Zeroizing;

use super::get_vault_id;
use crate::crypto::keys::Vkek;
use crate::store::sqlite;
use crate::store::sqlite::SlotKind;

/// A failed unlock attempt for a single auth slot.
struct UnlockAttempt {
    slot_id: i64,
    kind: SlotKind,
    error: anyhow::Error,
    is_backend_failure: bool,
}

/// Heuristic: returns `true` if the error looks like an actual backend/infra
/// failure rather than a normal "key not found / wrong passphrase" miss.
///
/// Conservative: anything we don't recognise is treated as a backend failure
/// (better to over-report than silently swallow).
fn is_backend_failure(e: &anyhow::Error) -> bool {
    let msg = format!("{e:#}").to_lowercase();

    // Expected misses — these are normal "try next slot" conditions.
    let expected_patterns = [
        "not found",
        "wrong passphrase",
        "incorrect passphrase",
        "passphrase slot missing salt",
        "invalid wrapped vkek blob",
        "agent not running",
        "no agent",
        "decryption failed",
        "aead",
        "vkek not found in keyring",
    ];

    for pat in &expected_patterns {
        if msg.contains(pat) {
            return false;
        }
    }

    // If none of the expected patterns matched, treat it as a backend failure.
    true
}

/// Cache the VKEK in the agent, warning on failure instead of silently dropping.
/// Suppresses warnings when the agent simply isn't running (expected case).
#[cfg(unix)]
fn cache_vkek_in_agent(vkek: &Vkek, vault_id: &str) {
    if let Err(e) = crate::agent::client::store_vkek_for_vault(vkek, Some(vault_id)) {
        let msg = format!("{e}").to_lowercase();
        // Agent not running is expected — don't warn about it
        if !msg.contains("no such file") && !msg.contains("connection refused") && !msg.contains("not running") {
            eprintln!("Warning: failed to cache VKEK in agent: {e}");
        }
    }
}

/// Build a diagnostic error message from collected unlock failures.
fn build_unlock_error(attempts: &[UnlockAttempt], fallback_msg: &str) -> anyhow::Error {
    let backend_failures: Vec<&UnlockAttempt> =
        attempts.iter().filter(|a| a.is_backend_failure).collect();

    if backend_failures.is_empty() {
        // Only expected misses — use the original generic message.
        return anyhow::anyhow!("{fallback_msg}");
    }

    let mut msg = String::from("Auth backend errors encountered during unlock:\n");
    for fail in &backend_failures {
        msg.push_str(&format!(
            "  - {} slot (id {}): {:#}\n",
            fail.kind, fail.slot_id, fail.error
        ));
    }
    msg.push_str(fallback_msg);
    msg.push_str("\nHint: run `vault doctor` for diagnostics");
    anyhow::anyhow!("{msg}")
}

/// Unlock the vault and return the VKEK.
/// Tries agent first (unix only), then auth slots.
pub fn unlock_vault(conn: &Connection) -> Result<Vkek> {
    let vault_id = get_vault_id(conn)?;
    let mut attempts: Vec<UnlockAttempt> = Vec::new();

    // Try agent first (unix only)
    #[cfg(unix)]
    {
        if crate::agent::client::is_agent_running_for_vault(Some(&vault_id)) {
            if let Ok(vkek) = crate::agent::client::get_vkek_for_vault(Some(&vault_id)) {
                return Ok(vkek);
            }
        }
    }

    // Try trust-local slots (Linux only)
    #[cfg(target_os = "linux")]
    {
        let slots = sqlite::get_auth_slots(conn, SlotKind::TrustLocal)?;
        for slot in &slots {
            match crate::auth::slot::unwrap_trust_local_slot(slot, &vault_id) {
                Ok(vkek) => {
                    #[cfg(unix)]
                    cache_vkek_in_agent(&vkek, &vault_id);
                    return Ok(vkek);
                }
                Err(e) => {
                    let backend = is_backend_failure(&e);
                    attempts.push(UnlockAttempt {
                        slot_id: slot.id,
                        kind: SlotKind::TrustLocal,
                        error: e,
                        is_backend_failure: backend,
                    });
                }
            }
        }
    }

    // Try TPM2 slots (Linux)
    #[cfg(target_os = "linux")]
    {
        let slots = sqlite::get_auth_slots(conn, SlotKind::Tpm)?;
        for slot in &slots {
            match crate::auth::slot::unwrap_tpm_slot(slot) {
                Ok(vkek) => {
                    cache_vkek_in_agent(&vkek, &vault_id);
                    return Ok(vkek);
                }
                Err(e) => {
                    let backend = is_backend_failure(&e);
                    attempts.push(UnlockAttempt {
                        slot_id: slot.id,
                        kind: SlotKind::Tpm,
                        error: e,
                        is_backend_failure: backend,
                    });
                }
            }
        }
    }

    // Try Keychain slots (macOS)
    #[cfg(target_os = "macos")]
    {
        let slots = sqlite::get_auth_slots(conn, SlotKind::Keychain)?;
        for slot in &slots {
            match crate::auth::slot::unwrap_keychain_slot(slot) {
                Ok(vkek) => {
                    cache_vkek_in_agent(&vkek, &vault_id);
                    return Ok(vkek);
                }
                Err(e) => {
                    let backend = is_backend_failure(&e);
                    attempts.push(UnlockAttempt {
                        slot_id: slot.id,
                        kind: SlotKind::Keychain,
                        error: e,
                        is_backend_failure: backend,
                    });
                }
            }
        }
    }

    // Try DPAPI slots (Windows)
    #[cfg(target_os = "windows")]
    {
        let slots = sqlite::get_auth_slots(conn, SlotKind::Dpapi)?;
        for slot in &slots {
            match crate::auth::slot::unwrap_dpapi_slot(slot) {
                Ok(vkek) => {
                    cache_vkek_in_agent(&vkek, &vault_id);
                    return Ok(vkek);
                }
                Err(e) => {
                    let backend = is_backend_failure(&e);
                    attempts.push(UnlockAttempt {
                        slot_id: slot.id,
                        kind: SlotKind::Dpapi,
                        error: e,
                        is_backend_failure: backend,
                    });
                }
            }
        }
    }

    // Try passphrase slots
    let slots = sqlite::get_auth_slots(conn, SlotKind::Passphrase)?;
    if !slots.is_empty() {
        let passphrase = Zeroizing::new(crate::auth::passphrase::prompt_passphrase(false)?);
        for slot in &slots {
            match crate::auth::slot::unwrap_passphrase_slot(slot, passphrase.as_slice()) {
                Ok(vkek) => {
                    #[cfg(unix)]
                    cache_vkek_in_agent(&vkek, &vault_id);
                    return Ok(vkek);
                }
                Err(e) => {
                    let backend = is_backend_failure(&e);
                    attempts.push(UnlockAttempt {
                        slot_id: slot.id,
                        kind: SlotKind::Passphrase,
                        error: e,
                        is_backend_failure: backend,
                    });
                }
            }
        }
        return Err(build_unlock_error(&attempts, "incorrect passphrase"));
    }

    Err(build_unlock_error(
        &attempts,
        "no suitable auth slot found; is the vault initialized?",
    ))
}
