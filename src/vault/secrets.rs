use anyhow::{Context, Result};
use rusqlite::Connection;
use zeroize::Zeroizing;

use super::{name_aad, validate_secret_name, validate_secret_value, value_aad};
use crate::crypto::{self, keys::Vkek};
use crate::store::sqlite;

/// Store a secret in the vault.
pub fn set_secret(conn: &Connection, vkek: &Vkek, name: &str, value: &[u8]) -> Result<()> {
    validate_secret_name(name)?;
    validate_secret_value(value)?;

    let blind_idx = crypto::hmac::blind_index(vkek, name);
    let name_aad = name_aad(&blind_idx);
    let value_aad = value_aad(&blind_idx);

    let rdek = crypto::keys::Rdek::generate();

    let (encrypted_name, name_iv) =
        crypto::aes::encrypt_with_aad(rdek.as_bytes(), name.as_bytes(), &name_aad)
            .context("failed to encrypt secret name")?;
    let (encrypted_value, value_iv) =
        crypto::aes::encrypt_with_aad(rdek.as_bytes(), value, &value_aad)
            .context("failed to encrypt secret value")?;
    let (wrapped_rdek, rdek_iv) = rdek
        .wrap_with_aad(vkek, &blind_idx)
        .context("failed to wrap RDEK")?;

    sqlite::upsert_secret(
        conn,
        &sqlite::SecretRecord {
            blind_index: &blind_idx,
            encrypted_name: &encrypted_name,
            name_nonce: &name_iv,
            encrypted_value: &encrypted_value,
            value_nonce: &value_iv,
            wrapped_rdek: &wrapped_rdek,
            rdek_nonce: &rdek_iv,
        },
    )?;

    Ok(())
}

/// Retrieve a secret from the vault.
pub fn get_secret(conn: &Connection, vkek: &Vkek, name: &str) -> Result<Vec<u8>> {
    validate_secret_name(name)?;
    let blind_idx = crypto::hmac::blind_index(vkek, name);
    let row = sqlite::get_secret(conn, &blind_idx)?
        .ok_or_else(|| anyhow::anyhow!("secret '{}' not found", name))?;

    let nonce: [u8; 12] = row
        .rdek_iv
        .as_slice()
        .try_into()
        .context("invalid RDEK IV length")?;
    let rdek = crypto::keys::Rdek::unwrap_with_aad(vkek, &row.wrapped_rdek, &nonce, &blind_idx)?;

    let name_nonce: [u8; 12] = row
        .name_iv
        .as_slice()
        .try_into()
        .context("invalid name IV length")?;
    let decrypted_name = Zeroizing::new(
        crypto::aes::decrypt_with_aad(
            rdek.as_bytes(),
            &row.encrypted_name,
            &name_nonce,
            &name_aad(&blind_idx),
        )
        .context("failed to decrypt secret name")?,
    );
    if decrypted_name.as_slice() != name.as_bytes() {
        anyhow::bail!("secret name integrity check failed");
    }

    let value_nonce: [u8; 12] = row
        .value_iv
        .as_slice()
        .try_into()
        .context("invalid value IV length")?;
    let value = Zeroizing::new(
        crypto::aes::decrypt_with_aad(
            rdek.as_bytes(),
            &row.encrypted_value,
            &value_nonce,
            &value_aad(&blind_idx),
        )
        .context("failed to decrypt secret value")?,
    );

    Ok(value.to_vec())
}

/// List all secret names in the vault.
pub fn list_secrets(conn: &Connection, vkek: &Vkek) -> Result<Vec<String>> {
    let rows = sqlite::get_all_secrets(conn)?;
    let mut names = Vec::with_capacity(rows.len());

    for row in &rows {
        let nonce: [u8; 12] = row
            .rdek_iv
            .as_slice()
            .try_into()
            .context("invalid RDEK IV length")?;
        let rdek =
            crypto::keys::Rdek::unwrap_with_aad(vkek, &row.wrapped_rdek, &nonce, &row.blind_index)?;

        let name_nonce: [u8; 12] = row
            .name_iv
            .as_slice()
            .try_into()
            .context("invalid name IV length")?;
        let name_bytes = Zeroizing::new(
            crypto::aes::decrypt_with_aad(
                rdek.as_bytes(),
                &row.encrypted_name,
                &name_nonce,
                &name_aad(&row.blind_index),
            )
            .context("failed to decrypt secret name")?,
        );

        names.push(
            String::from_utf8(name_bytes.to_vec()).context("secret name is not valid UTF-8")?,
        );
    }

    Ok(names)
}

/// Delete a secret from the vault.
pub fn delete_secret(conn: &Connection, vkek: &Vkek, name: &str) -> Result<bool> {
    validate_secret_name(name)?;
    let blind_idx = crypto::hmac::blind_index(vkek, name);
    let deleted = sqlite::delete_secret(conn, &blind_idx)?;
    if deleted {
        if let Err(e) = sqlite::vacuum(conn) {
            eprintln!("Warning: post-delete VACUUM failed: {e}");
        }
    }
    Ok(deleted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::sqlite;
    use rusqlite::Connection;

    fn setup() -> (Connection, Vkek) {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        sqlite::init_schema(&conn).unwrap();
        sqlite::set_meta(&conn, "vault_id", b"test-vault").unwrap();
        let vkek = Vkek::generate();
        (conn, vkek)
    }

    #[test]
    fn test_set_get_round_trip() {
        let (conn, vkek) = setup();
        set_secret(&conn, &vkek, "my-secret", b"hunter2").unwrap();
        let val = get_secret(&conn, &vkek, "my-secret").unwrap();
        assert_eq!(val, b"hunter2");
    }

    #[test]
    fn test_get_nonexistent_secret() {
        let (conn, vkek) = setup();
        let err = get_secret(&conn, &vkek, "nope");
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn test_list_secrets_empty() {
        let (conn, vkek) = setup();
        let names = list_secrets(&conn, &vkek).unwrap();
        assert!(names.is_empty());
    }

    #[test]
    fn test_list_secrets_multiple() {
        let (conn, vkek) = setup();
        set_secret(&conn, &vkek, "alpha", b"1").unwrap();
        set_secret(&conn, &vkek, "beta", b"2").unwrap();
        set_secret(&conn, &vkek, "gamma", b"3").unwrap();
        let mut names = list_secrets(&conn, &vkek).unwrap();
        names.sort();
        assert_eq!(names, vec!["alpha", "beta", "gamma"]);
    }

    #[test]
    fn test_delete_secret() {
        let (conn, vkek) = setup();
        set_secret(&conn, &vkek, "to-delete", b"val").unwrap();
        assert!(delete_secret(&conn, &vkek, "to-delete").unwrap());
        assert!(get_secret(&conn, &vkek, "to-delete").is_err());
    }

    #[test]
    fn test_overwrite_secret() {
        let (conn, vkek) = setup();
        set_secret(&conn, &vkek, "key", b"old").unwrap();
        set_secret(&conn, &vkek, "key", b"new").unwrap();
        let val = get_secret(&conn, &vkek, "key").unwrap();
        assert_eq!(val, b"new");
    }

    #[test]
    fn test_secret_name_validation() {
        let (conn, vkek) = setup();
        assert!(set_secret(&conn, &vkek, "", b"v").is_err());
        assert!(set_secret(&conn, &vkek, "bad\x00name", b"v").is_err());
        let long = "x".repeat(256);
        assert!(set_secret(&conn, &vkek, &long, b"v").is_err());
    }
}

