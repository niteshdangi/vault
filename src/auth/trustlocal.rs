//! Level 0: Trust-local authentication using Linux kernel keyring.
//!
//! NOTE: Trust-local is a convenience-only auth method. It is NOT a security
//! boundary — it relies on the machine-id and kernel keyring, both of which are
//! accessible to any process running as the same user. A passphrase slot should
//! always be the primary auth method; trust-local merely avoids re-prompting on
//! trusted single-user machines.

use anyhow::Result;
use zeroize::Zeroizing;

use crate::crypto::keys::Vkek;

fn keyring_desc(vault_id: &str) -> String {
    format!("vault:vkek:{}", vault_id)
}

/// Store the VKEK in the Linux kernel user session keyring.
pub fn store_in_keyring(vkek: &Vkek, vault_id: &str) -> Result<()> {
    use linux_keyutils::{KeyRing, KeyRingIdentifier};

    let desc = keyring_desc(vault_id);
    let ring = KeyRing::from_special_id(KeyRingIdentifier::Session, false)
        .map_err(|e| anyhow::anyhow!("failed to access session keyring: {}", e))?;

    ring.add_key(&desc, vkek.as_bytes())
        .map_err(|e| anyhow::anyhow!("failed to store key in keyring: {}", e))?;

    Ok(())
}

/// Load the VKEK from the Linux kernel user session keyring.
pub fn load_from_keyring(vault_id: &str) -> Result<Vkek> {
    use linux_keyutils::{KeyRing, KeyRingIdentifier};

    let desc = keyring_desc(vault_id);
    let ring = KeyRing::from_special_id(KeyRingIdentifier::Session, false)
        .map_err(|e| anyhow::anyhow!("failed to access session keyring: {}", e))?;

    let key = ring
        .search(&desc)
        .map_err(|e| anyhow::anyhow!("VKEK not found in keyring: {}", e))?;

    let mut buf = Zeroizing::new(vec![0u8; 32]);
    let len = key
        .read(&mut buf)
        .map_err(|e| anyhow::anyhow!("failed to read VKEK from keyring: {}", e))?;

    if len != 32 {
        anyhow::bail!("invalid VKEK length in keyring: {}", len);
    }

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&buf[..32]);
    Ok(Vkek::from_bytes(bytes))
}

/// Remove the VKEK from the kernel keyring.
pub fn clear_keyring(vault_id: &str) -> Result<()> {
    use linux_keyutils::{KeyRing, KeyRingIdentifier};

    let desc = keyring_desc(vault_id);
    let ring = KeyRing::from_special_id(KeyRingIdentifier::Session, false)
        .map_err(|e| anyhow::anyhow!("failed to access session keyring: {}", e))?;

    if let Ok(key) = ring.search(&desc) {
        key.invalidate()
            .map_err(|e| anyhow::anyhow!("failed to invalidate keyring key: {}", e))?;
    }

    Ok(())
}

/// Get or create a machine-local key for trust-local wrapping.
/// Fails closed if no machine-id is available — never uses a hardcoded fallback.
pub fn get_or_create_machine_key() -> Result<[u8; 32]> {
    let machine_id = std::fs::read_to_string("/etc/machine-id")
        .or_else(|_| std::fs::read_to_string("/var/lib/dbus/machine-id"))
        .map_err(|_| {
            anyhow::anyhow!(
                "machine-id not found at /etc/machine-id or /var/lib/dbus/machine-id. \
             Trust-local auth requires a stable machine identifier. \
             Use passphrase auth instead, or create /etc/machine-id."
            )
        })?;

    let trimmed = machine_id.trim();
    if trimmed.is_empty() {
        anyhow::bail!("machine-id file is empty — cannot derive trust-local key");
    }

    let key =
        crate::crypto::keys::hkdf_sha256(trimmed.as_bytes(), b"vault-trust-local-machine-key-v1");

    Ok(key)
}
