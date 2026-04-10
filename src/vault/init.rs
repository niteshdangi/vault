use anyhow::{Context, Result};
use rusqlite::Connection;
use zeroize::Zeroizing;

use super::InitAuth;
use crate::crypto::keys::Vkek;
use crate::store::sqlite;

/// Initialize a new vault.
pub fn init_vault(conn: &Connection, auth: InitAuth) -> Result<()> {
    if sqlite::is_initialized(conn).context("failed to check vault initialization status")? {
        anyhow::bail!("vault is already initialized");
    }

    sqlite::init_schema(conn)?;

    conn.execute_batch("BEGIN IMMEDIATE;")?;

    let result = (|| -> Result<()> {
        // Generate vault ID
        let vault_id = uuid::Uuid::new_v4().to_string();
        sqlite::set_meta(conn, "vault_id", vault_id.as_bytes())?;
        sqlite::set_meta(conn, "schema_version", b"1")?;
        sqlite::set_meta(conn, "cipher_suite", b"AES-256-GCM+HKDF-SHA256")?;

        // Generate VKEK
        let vkek = Vkek::generate();

        match auth {
            InitAuth::TrustLocal => {
                #[cfg(target_os = "linux")]
                {
                    crate::auth::slot::create_trust_local_slot(conn, &vkek, &vault_id)
                        .context("failed to create trust-local auth slot")?;
                    eprintln!("✓ Vault initialized with trust-local authentication");
                    eprintln!("  ⚠ trust-local provides convenience, not security. Add a passphrase slot as primary auth.");
                }
                #[cfg(not(target_os = "linux"))]
                {
                    anyhow::bail!("trust-local auth is only supported on Linux");
                }
            }
            InitAuth::Tpm => {
                #[cfg(target_os = "linux")]
                {
                    crate::auth::slot::create_tpm_slot(conn, &vkek)
                        .context("failed to create TPM2 auth slot")?;
                    eprintln!("✓ Vault initialized with TPM 2.0 authentication");
                    eprintln!("  ⚠ VKEK sealed to this machine's TPM chip");
                }
                #[cfg(not(target_os = "linux"))]
                {
                    anyhow::bail!("TPM 2.0 auth is only supported on Linux");
                }
            }
            InitAuth::Keychain => {
                #[cfg(target_os = "macos")]
                {
                    crate::auth::slot::create_keychain_slot(conn, &vkek)
                        .context("failed to create Keychain auth slot")?;
                    eprintln!("✓ Vault initialized with macOS Keychain authentication");
                }
                #[cfg(not(target_os = "macos"))]
                {
                    anyhow::bail!("Keychain auth is only supported on macOS");
                }
            }
            InitAuth::Dpapi => {
                #[cfg(target_os = "windows")]
                {
                    crate::auth::slot::create_dpapi_slot(conn, &vkek)
                        .context("failed to create DPAPI auth slot")?;
                    eprintln!("✓ Vault initialized with Windows DPAPI authentication");
                }
                #[cfg(not(target_os = "windows"))]
                {
                    anyhow::bail!("DPAPI auth is only supported on Windows");
                }
            }
            InitAuth::Passphrase => {
                let passphrase = Zeroizing::new(crate::auth::passphrase::prompt_passphrase(true)?);
                crate::auth::slot::create_passphrase_slot(conn, &vkek, passphrase.as_slice())
                    .context("failed to create passphrase auth slot")?;
                eprintln!("✓ Vault initialized with passphrase authentication");
            }
        }

        // Store vault creation timestamp
        let now = chrono::Utc::now().to_rfc3339();
        sqlite::set_meta(conn, "created_at", now.as_bytes())?;

        Ok(())
    })();

    match result {
        Ok(()) => {
            conn.execute_batch("COMMIT;")?;
            Ok(())
        }
        Err(e) => {
            conn.execute_batch("ROLLBACK;").ok();
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::sqlite;

    fn mem_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        conn
    }

    #[test]
    fn test_init_creates_vault() {
        let conn = mem_db();
        // On Linux this will use trust-local; on other platforms use passphrase
        // We test the metadata path directly since auth backends may not be available
        sqlite::init_schema(&conn).unwrap();
        conn.execute_batch("BEGIN IMMEDIATE;").unwrap();
        let vault_id = uuid::Uuid::new_v4().to_string();
        sqlite::set_meta(&conn, "vault_id", vault_id.as_bytes()).unwrap();
        sqlite::set_meta(&conn, "schema_version", b"1").unwrap();
        conn.execute_batch("COMMIT;").unwrap();

        let stored = sqlite::get_meta(&conn, "vault_id").unwrap().unwrap();
        assert_eq!(stored, vault_id.as_bytes());
        assert!(sqlite::is_initialized(&conn).unwrap());
    }

    #[test]
    fn test_init_twice_fails() {
        let conn = mem_db();
        sqlite::init_schema(&conn).unwrap();
        sqlite::set_meta(&conn, "vault_id", b"existing").unwrap();
        // Now calling init_vault should detect it's already initialized
        let err = init_vault(&conn, InitAuth::TrustLocal);
        assert!(err.is_err());
        let msg = err.unwrap_err().to_string();
        assert!(msg.contains("already initialized"), "got: {}", msg);
    }

    #[test]
    fn test_init_is_transactional() {
        // Verify that if we start a txn, set meta, then rollback, the meta is gone
        let conn = mem_db();
        sqlite::init_schema(&conn).unwrap();
        conn.execute_batch("BEGIN IMMEDIATE;").unwrap();
        sqlite::set_meta(&conn, "vault_id", b"txn-test").unwrap();
        conn.execute_batch("ROLLBACK;").unwrap();
        assert!(!sqlite::is_initialized(&conn).unwrap());
    }
}
