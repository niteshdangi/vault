//! SQLite storage backend for the vault.

use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use std::path::{Path, PathBuf};

/// Get the default vault database path.
pub fn default_db_path() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        PathBuf::from(xdg).join("vault").join("vault.db")
    } else if let Some(home) = dirs::home_dir() {
        home.join(".local/share/vault/vault.db")
    } else {
        PathBuf::from("vault.db")
    }
}

/// Open (or create) the vault database and initialize the schema.
pub fn open_db(path: &Path) -> Result<Connection> {
    if let Some(parent) = path.parent() {
        // Create parent with restrictive permissions (0700).
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .with_context(|| format!("failed to create directory: {}", parent.display()))?;
        }
        #[cfg(not(unix))]
        {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create directory: {}", parent.display()))?;
        }
    }

    // Set restrictive umask before DB open so WAL/SHM files are created safely.
    #[cfg(unix)]
    let old_umask = nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o077));

    let conn = Connection::open(path)
        .with_context(|| format!("failed to open database: {}", path.display()));

    // Restore the original umask immediately after DB open so we don't
    // affect the rest of the process.
    #[cfg(unix)]
    nix::sys::stat::umask(old_umask);

    let conn = conn?;

    // Security: restrict permissions on the DB file
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        if let Err(e) = std::fs::set_permissions(path, perms) {
            eprintln!("Warning: failed to set permissions on {}: {e}", path.display());
        }
        // Also restrict WAL and SHM files if they exist.
        for suffix in &["-wal", "-shm"] {
            let aux = path.with_extension(format!("db{}", suffix));
            if aux.exists() {
                if let Err(e) = std::fs::set_permissions(&aux, std::fs::Permissions::from_mode(0o600)) {
                    eprintln!("Warning: failed to set permissions on {}: {e}", aux.display());
                }
            }
            // Also try the "vault.db-wal" form
            let aux2 = PathBuf::from(format!("{}{}", path.display(), suffix));
            if aux2.exists() {
                if let Err(e) = std::fs::set_permissions(&aux2, std::fs::Permissions::from_mode(0o600)) {
                    eprintln!("Warning: failed to set permissions on {}: {e}", aux2.display());
                }
            }
        }
    }

    // Enable WAL mode for better concurrent access
    conn.execute_batch("PRAGMA journal_mode=WAL;")?;
    conn.execute_batch("PRAGMA foreign_keys=ON;")?;
    // Security: overwrite deleted content with zeros
    conn.execute_batch("PRAGMA secure_delete=ON;")?;

    Ok(conn)
}

/// Initialize the database schema.
pub fn init_schema(conn: &Connection) -> Result<()> {
    // Enable full auto-vacuum so freed pages are reclaimed (reducing ciphertext residue).
    conn.execute_batch("PRAGMA auto_vacuum=FULL;")?;

    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS vault_meta (
            key TEXT PRIMARY KEY,
            value BLOB
        );

        CREATE TABLE IF NOT EXISTS auth_slots (
            id INTEGER PRIMARY KEY,
            slot_type TEXT NOT NULL,
            wrapped_vkek BLOB NOT NULL,
            salt BLOB,
            params TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS secrets (
            id INTEGER PRIMARY KEY,
            blind_index BLOB UNIQUE NOT NULL,
            encrypted_name BLOB NOT NULL,
            name_iv BLOB NOT NULL,
            encrypted_value BLOB NOT NULL,
            value_iv BLOB NOT NULL,
            wrapped_rdek BLOB NOT NULL,
            rdek_iv BLOB NOT NULL,
            created_at TEXT DEFAULT (datetime('now')),
            updated_at TEXT DEFAULT (datetime('now'))
        );
        ",
    )?;
    Ok(())
}

/// Vacuum the database (maintenance — reclaims space, removes residue).
pub fn vacuum(conn: &Connection) -> Result<()> {
    conn.execute_batch("VACUUM;")?;
    Ok(())
}

/// Set a vault metadata value.
pub fn set_meta(conn: &Connection, key: &str, value: &[u8]) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO vault_meta (key, value) VALUES (?1, ?2)",
        params![key, value],
    )?;
    Ok(())
}

/// Get a vault metadata value.
pub fn get_meta(conn: &Connection, key: &str) -> Result<Option<Vec<u8>>> {
    let mut stmt = conn.prepare("SELECT value FROM vault_meta WHERE key = ?1")?;
    match stmt.query_row(params![key], |row| row.get::<_, Vec<u8>>(0)) {
        Ok(val) => Ok(Some(val)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Insert an auth slot.
pub fn insert_auth_slot(
    conn: &Connection,
    kind: SlotKind,
    wrapped_vkek: &[u8],
    salt: Option<&[u8]>,
    params_json: Option<&str>,
) -> Result<i64> {
    conn.execute(
        "INSERT INTO auth_slots (slot_type, wrapped_vkek, salt, params) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![kind.as_str(), wrapped_vkek, salt, params_json],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Get auth slots by kind.
pub fn get_auth_slots(conn: &Connection, kind: SlotKind) -> Result<Vec<AuthSlotRow>> {
    let mut stmt = conn.prepare(
        "SELECT id, slot_type, wrapped_vkek, salt, params, created_at FROM auth_slots WHERE slot_type = ?1",
    )?;
    let rows = stmt.query_map(params![kind.as_str()], |row| {
        let type_str: String = row.get(1)?;
        Ok(AuthSlotRow {
            id: row.get(0)?,
            kind: SlotKind::parse(&type_str).unwrap_or(SlotKind::Passphrase),
            wrapped_vkek: row.get(2)?,
            salt: row.get(3)?,
            params: row.get(4)?,
            created_at: row.get(5)?,
        })
    })?;

    let mut result = Vec::new();
    for row in rows {
        result.push(row?);
    }
    Ok(result)
}

/// Get all auth slots.
pub fn get_all_auth_slots(conn: &Connection) -> Result<Vec<AuthSlotRow>> {
    let mut stmt = conn
        .prepare("SELECT id, slot_type, wrapped_vkek, salt, params, created_at FROM auth_slots")?;
    let rows = stmt.query_map([], |row| {
        let type_str: String = row.get(1)?;
        Ok(AuthSlotRow {
            id: row.get(0)?,
            kind: SlotKind::parse(&type_str).unwrap_or(SlotKind::Passphrase),
            wrapped_vkek: row.get(2)?,
            salt: row.get(3)?,
            params: row.get(4)?,
            created_at: row.get(5)?,
        })
    })?;

    let mut result = Vec::new();
    for row in rows {
        result.push(row?);
    }
    Ok(result)
}

/// The kind of authentication slot.
#[derive(Debug, Clone, PartialEq)]
pub enum SlotKind {
    Passphrase,
    TrustLocal,
    Tpm,
    Keychain,
    Dpapi,
}

impl SlotKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            SlotKind::Passphrase => "passphrase",
            SlotKind::TrustLocal => "trust-local",
            SlotKind::Tpm => "tpm2",
            SlotKind::Keychain => "keychain",
            SlotKind::Dpapi => "dpapi",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "passphrase" => Some(SlotKind::Passphrase),
            "trust-local" => Some(SlotKind::TrustLocal),
            "tpm" | "tpm2" => Some(SlotKind::Tpm),
            "keychain" => Some(SlotKind::Keychain),
            "dpapi" => Some(SlotKind::Dpapi),
            _ => None,
        }
    }
}

impl std::fmt::Display for SlotKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct AuthSlotRow {
    pub id: i64,
    pub kind: SlotKind,
    pub wrapped_vkek: Vec<u8>,
    pub salt: Option<Vec<u8>>,
    pub params: Option<String>,
    pub created_at: Option<String>,
}

/// Record for writing a secret to the store.
pub struct SecretRecord<'a> {
    pub blind_index: &'a [u8],
    pub encrypted_name: &'a [u8],
    pub name_nonce: &'a [u8],
    pub encrypted_value: &'a [u8],
    pub value_nonce: &'a [u8],
    pub wrapped_rdek: &'a [u8],
    pub rdek_nonce: &'a [u8],
}

/// Insert or update a secret.
pub fn upsert_secret(conn: &Connection, rec: &SecretRecord<'_>) -> Result<()> {
    conn.execute(
        "INSERT INTO secrets (blind_index, encrypted_name, name_iv, encrypted_value, value_iv, wrapped_rdek, rdek_iv)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(blind_index) DO UPDATE SET
            encrypted_name = excluded.encrypted_name,
            name_iv = excluded.name_iv,
            encrypted_value = excluded.encrypted_value,
            value_iv = excluded.value_iv,
            wrapped_rdek = excluded.wrapped_rdek,
            rdek_iv = excluded.rdek_iv,
            updated_at = datetime('now')",
        rusqlite::params![rec.blind_index, rec.encrypted_name, rec.name_nonce, rec.encrypted_value, rec.value_nonce, rec.wrapped_rdek, rec.rdek_nonce],
    )?;
    Ok(())
}

/// Get a secret by blind index.
pub fn get_secret(conn: &Connection, blind_index: &[u8]) -> Result<Option<SecretRow>> {
    let mut stmt = conn.prepare(
        "SELECT id, blind_index, encrypted_name, name_iv, encrypted_value, value_iv, wrapped_rdek, rdek_iv, created_at, updated_at
         FROM secrets WHERE blind_index = ?1",
    )?;
    let result = stmt.query_row(params![blind_index], |row| {
        Ok(SecretRow {
            id: row.get(0)?,
            blind_index: row.get(1)?,
            encrypted_name: row.get(2)?,
            name_iv: row.get(3)?,
            encrypted_value: row.get(4)?,
            value_iv: row.get(5)?,
            wrapped_rdek: row.get(6)?,
            rdek_iv: row.get(7)?,
            created_at: row.get(8)?,
            updated_at: row.get(9)?,
        })
    });
    match result {
        Ok(row) => Ok(Some(row)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Get all secrets (for listing).
pub fn get_all_secrets(conn: &Connection) -> Result<Vec<SecretRow>> {
    let mut stmt = conn.prepare(
        "SELECT id, blind_index, encrypted_name, name_iv, encrypted_value, value_iv, wrapped_rdek, rdek_iv, created_at, updated_at
         FROM secrets ORDER BY id",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(SecretRow {
            id: row.get(0)?,
            blind_index: row.get(1)?,
            encrypted_name: row.get(2)?,
            name_iv: row.get(3)?,
            encrypted_value: row.get(4)?,
            value_iv: row.get(5)?,
            wrapped_rdek: row.get(6)?,
            rdek_iv: row.get(7)?,
            created_at: row.get(8)?,
            updated_at: row.get(9)?,
        })
    })?;

    let mut result = Vec::new();
    for row in rows {
        result.push(row?);
    }
    Ok(result)
}

/// Delete a secret by blind index.
pub fn delete_secret(conn: &Connection, blind_index: &[u8]) -> Result<bool> {
    let affected = conn.execute(
        "DELETE FROM secrets WHERE blind_index = ?1",
        params![blind_index],
    )?;
    Ok(affected > 0)
}

/// Count secrets in the vault.
pub fn count_secrets(conn: &Connection) -> Result<i64> {
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM secrets", [], |row| row.get(0))?;
    Ok(count)
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct SecretRow {
    pub id: i64,
    pub blind_index: Vec<u8>,
    pub encrypted_name: Vec<u8>,
    pub name_iv: Vec<u8>,
    pub encrypted_value: Vec<u8>,
    pub value_iv: Vec<u8>,
    pub wrapped_rdek: Vec<u8>,
    pub rdek_iv: Vec<u8>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

/// Check if the vault database is initialized.
pub fn is_initialized(conn: &Connection) -> Result<bool> {
    match get_meta(conn, "vault_id") {
        Ok(Some(_)) => Ok(true),
        Ok(None) => Ok(false),
        Err(e) => {
            // If the table doesn't exist yet, the vault is not initialized
            let msg = e.to_string();
            if msg.contains("no such table") {
                Ok(false)
            } else {
                Err(e)
            }
        }
    }
}

/// Get a single auth slot by ID.
pub fn get_auth_slot_by_id(conn: &Connection, slot_id: i64) -> Result<Option<AuthSlotRow>> {
    let mut stmt = conn.prepare(
        "SELECT id, slot_type, wrapped_vkek, salt, params, created_at FROM auth_slots WHERE id = ?1",
    )?;
    let mut rows = stmt.query_map(params![slot_id], |row| {
        let type_str: String = row.get(1)?;
        Ok(AuthSlotRow {
            id: row.get(0)?,
            kind: SlotKind::parse(&type_str).unwrap_or(SlotKind::Passphrase),
            wrapped_vkek: row.get(2)?,
            salt: row.get(3)?,
            params: row.get(4)?,
            created_at: row.get(5)?,
        })
    })?;
    match rows.next() {
        Some(Ok(row)) => Ok(Some(row)),
        Some(Err(e)) => Err(e.into()),
        None => Ok(None),
    }
}

/// Delete an auth slot by ID.
pub fn delete_auth_slot(conn: &Connection, slot_id: i64) -> Result<bool> {
    let affected = conn.execute("DELETE FROM auth_slots WHERE id = ?1", params![slot_id])?;
    Ok(affected > 0)
}

/// Count auth slots.
pub fn count_auth_slots(conn: &Connection) -> Result<i64> {
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM auth_slots", [], |row| row.get(0))?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn mem_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
        conn
    }

    #[test]
    fn test_init_schema_creates_tables() {
        let conn = mem_db();
        init_schema(&conn).unwrap();
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();
        assert!(tables.contains(&"vault_meta".to_string()));
        assert!(tables.contains(&"auth_slots".to_string()));
        assert!(tables.contains(&"secrets".to_string()));
    }

    #[test]
    fn test_set_get_meta() {
        let conn = mem_db();
        init_schema(&conn).unwrap();
        set_meta(&conn, "foo", b"bar").unwrap();
        let val = get_meta(&conn, "foo").unwrap();
        assert_eq!(val, Some(b"bar".to_vec()));
    }

    #[test]
    fn test_is_initialized() {
        let conn = mem_db();
        init_schema(&conn).unwrap();
        assert!(!is_initialized(&conn).unwrap());
        set_meta(&conn, "vault_id", b"test-id").unwrap();
        assert!(is_initialized(&conn).unwrap());
    }

    #[test]
    fn test_store_get_secret() {
        let conn = mem_db();
        init_schema(&conn).unwrap();
        let blind = b"idx1".to_vec();
        upsert_secret(&conn, &SecretRecord {
            blind_index: &blind,
            encrypted_name: b"enc_n",
            name_nonce: b"niv",
            encrypted_value: b"enc_v",
            value_nonce: b"viv",
            wrapped_rdek: b"wrdek",
            rdek_nonce: b"riv",
        }).unwrap();
        let row = get_secret(&conn, &blind).unwrap();
        assert!(row.is_some());
        let row = row.unwrap();
        assert_eq!(row.encrypted_name, b"enc_n");
        assert_eq!(row.encrypted_value, b"enc_v");
    }

    #[test]
    fn test_get_nonexistent_secret() {
        let conn = mem_db();
        init_schema(&conn).unwrap();
        let row = get_secret(&conn, b"nope").unwrap();
        assert!(row.is_none());
    }

    #[test]
    fn test_delete_secret() {
        let conn = mem_db();
        init_schema(&conn).unwrap();
        let blind = b"idx2".to_vec();
        upsert_secret(&conn, &SecretRecord {
            blind_index: &blind,
            encrypted_name: b"n",
            name_nonce: b"ni",
            encrypted_value: b"v",
            value_nonce: b"vi",
            wrapped_rdek: b"w",
            rdek_nonce: b"r",
        }).unwrap();
        assert!(delete_secret(&conn, &blind).unwrap());
        assert!(get_secret(&conn, &blind).unwrap().is_none());
    }

    #[test]
    fn test_list_secrets() {
        let conn = mem_db();
        init_schema(&conn).unwrap();
        for i in 0..3 {
            let blind = format!("idx{}", i).into_bytes();
            upsert_secret(&conn, &SecretRecord {
                blind_index: &blind,
                encrypted_name: b"n",
                name_nonce: b"ni",
                encrypted_value: b"v",
                value_nonce: b"vi",
                wrapped_rdek: b"w",
                rdek_nonce: b"r",
            }).unwrap();
        }
        let all = get_all_secrets(&conn).unwrap();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_count_secrets() {
        let conn = mem_db();
        init_schema(&conn).unwrap();
        assert_eq!(count_secrets(&conn).unwrap(), 0);
        for i in 0..5 {
            let blind = format!("c{}", i).into_bytes();
            upsert_secret(&conn, &SecretRecord {
                blind_index: &blind,
                encrypted_name: b"n",
                name_nonce: b"ni",
                encrypted_value: b"v",
                value_nonce: b"vi",
                wrapped_rdek: b"w",
                rdek_nonce: b"r",
            }).unwrap();
        }
        assert_eq!(count_secrets(&conn).unwrap(), 5);
    }

    #[test]
    fn test_store_auth_slot_and_list() {
        let conn = mem_db();
        init_schema(&conn).unwrap();
        let id = insert_auth_slot(&conn, SlotKind::Passphrase, b"wrapped", Some(b"salt"), Some("{}")).unwrap();
        assert!(id > 0);
        let slots = get_all_auth_slots(&conn).unwrap();
        assert_eq!(slots.len(), 1);
        assert_eq!(slots[0].kind, SlotKind::Passphrase);
    }

    #[test]
    fn test_delete_auth_slot() {
        let conn = mem_db();
        init_schema(&conn).unwrap();
        let id = insert_auth_slot(&conn, SlotKind::Passphrase, b"blob", None, None).unwrap();
        assert!(delete_auth_slot(&conn, id).unwrap());
        let slots = get_all_auth_slots(&conn).unwrap();
        assert!(slots.is_empty());
    }
}
