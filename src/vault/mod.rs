//! High-level vault operations.

mod auth_mgmt;
mod diagnostics;
mod export;
mod init;
mod scope;
mod secrets;
mod status;
mod unlock;

// Re-export everything public
pub use auth_mgmt::*;
pub use diagnostics::*;
pub use export::*;
pub use init::*;
pub use scope::*;
pub use secrets::*;
pub use status::*;
pub use unlock::*;

use anyhow::{Context, Result};
use rusqlite::Connection;

pub(crate) const MAX_SECRET_NAME_BYTES: usize = 255;
pub(crate) const MAX_SECRET_VALUE_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_IMPORT_FILE_BYTES: usize = 50 * 1024 * 1024;
pub(crate) const MAX_IMPORT_SECRETS: usize = 10_000;
pub(crate) const MIN_EXPORT_KDF_TIME: u32 = 3;
pub(crate) const MIN_EXPORT_KDF_MEMORY: u32 = 65_536;

/// Auth method selection for vault init.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InitAuth {
    Passphrase,
    TrustLocal,
    Tpm,
    Keychain,
    Dpapi,
}

pub fn get_vault_id(conn: &Connection) -> Result<String> {
    let raw = crate::store::sqlite::get_meta(conn, "vault_id")?
        .ok_or_else(|| anyhow::anyhow!("vault is not initialized"))?;
    String::from_utf8(raw).context("vault_id is not valid UTF-8")
}

pub(crate) fn name_aad(blind_idx: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(5 + blind_idx.len());
    aad.extend_from_slice(b"name:");
    aad.extend_from_slice(blind_idx);
    aad
}

pub(crate) fn value_aad(blind_idx: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(6 + blind_idx.len());
    aad.extend_from_slice(b"value:");
    aad.extend_from_slice(blind_idx);
    aad
}

pub(crate) fn export_aad_bytes(
    version: u32,
    vault_id: &str,
    cipher: &str,
    kdf: &str,
    kdf_params: &KdfParams,
) -> Result<Vec<u8>> {
    let meta = serde_json::json!({
        "version": version,
        "vault_id": vault_id,
        "cipher": cipher,
        "kdf": kdf,
        "kdf_params": kdf_params,
    });
    let meta_json = serde_json::to_vec(&meta).context("failed to serialize export metadata AAD")?;
    let mut aad = Vec::with_capacity(7 + vault_id.len() + meta_json.len());
    aad.extend_from_slice(b"export:");
    aad.extend_from_slice(vault_id.as_bytes());
    aad.extend_from_slice(&meta_json);
    Ok(aad)
}

pub fn validate_secret_name(name: &str) -> Result<()> {
    if name.is_empty() {
        anyhow::bail!("secret name cannot be empty");
    }
    if name.len() > MAX_SECRET_NAME_BYTES {
        anyhow::bail!("secret name exceeds {} bytes", MAX_SECRET_NAME_BYTES);
    }
    if name.chars().any(|c| c.is_control()) {
        anyhow::bail!("secret name contains control characters");
    }
    for c in name.chars() {
        let allowed_ascii = c.is_ascii_graphic() || c == ' ';
        let allowed_unicode = !c.is_ascii() && !c.is_whitespace();
        if !(allowed_ascii || allowed_unicode) {
            anyhow::bail!("secret name contains unsupported characters");
        }
    }
    Ok(())
}

pub fn validate_secret_value(value: &[u8]) -> Result<()> {
    if value.len() > MAX_SECRET_VALUE_BYTES {
        anyhow::bail!("secret value exceeds {} bytes", MAX_SECRET_VALUE_BYTES);
    }
    Ok(())
}

pub fn validate_import_size(size: usize) -> Result<()> {
    if size > MAX_IMPORT_FILE_BYTES {
        anyhow::bail!("import file exceeds {} bytes", MAX_IMPORT_FILE_BYTES);
    }
    Ok(())
}

pub(crate) fn validate_export_kdf_params(params: &KdfParams) -> Result<()> {
    if params.memory < MIN_EXPORT_KDF_MEMORY {
        anyhow::bail!(
            "unsafe export KDF memory cost: {} (minimum {})",
            params.memory,
            MIN_EXPORT_KDF_MEMORY
        );
    }
    if params.time < MIN_EXPORT_KDF_TIME {
        anyhow::bail!(
            "unsafe export KDF time cost: {} (minimum {})",
            params.time,
            MIN_EXPORT_KDF_TIME
        );
    }
    if params.parallelism == 0 {
        anyhow::bail!("unsafe export KDF parallelism: 0");
    }
    Ok(())
}

/// Exported vault format.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct ExportEnvelope {
    pub version: u32,
    pub vault_id: String,
    pub exported_at: String,
    pub cipher: String,
    pub kdf: String,
    pub kdf_params: KdfParams,
    pub salt: String,
    pub nonce: String,
    pub data: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct KdfParams {
    pub time: u32,
    pub memory: u32,
    pub parallelism: u32,
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct ExportedSecret {
    pub name: String,
    pub value: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_secret_name_empty() {
        assert!(validate_secret_name("").is_err());
    }

    #[test]
    fn test_validate_secret_name_control_chars() {
        assert!(validate_secret_name("hello\x00world").is_err());
        assert!(validate_secret_name("tab\there").is_err());
        assert!(validate_secret_name("new\nline").is_err());
    }

    #[test]
    fn test_validate_secret_name_too_long() {
        let long = "a".repeat(256);
        assert!(validate_secret_name(&long).is_err());
    }

    #[test]
    fn test_validate_secret_name_valid() {
        assert!(validate_secret_name("my-secret").is_ok());
        assert!(validate_secret_name("API_KEY").is_ok());
        assert!(validate_secret_name("db/password").is_ok());
        assert!(validate_secret_name("a".repeat(255).as_str()).is_ok());
    }

    #[test]
    fn test_validate_secret_value_too_large() {
        let big = vec![0u8; MAX_SECRET_VALUE_BYTES + 1];
        assert!(validate_secret_value(&big).is_err());
        // Exactly at limit should pass
        let ok = vec![0u8; MAX_SECRET_VALUE_BYTES];
        assert!(validate_secret_value(&ok).is_ok());
    }

    #[test]
    fn test_validate_import_size() {
        assert!(validate_import_size(MAX_IMPORT_FILE_BYTES + 1).is_err());
        assert!(validate_import_size(MAX_IMPORT_FILE_BYTES).is_ok());
    }
}
