//! TPM 2.0 auth backend (Linux only).
//!
//! Uses tpm2-tools CLI commands as a portable wrapper rather than linking
//! against the tpm2-tss C library.  The VKEK is sealed to a TPM primary
//! storage key so it can only be recovered on the same physical machine.

#![cfg(target_os = "linux")]

use anyhow::{Context, Result};
use std::process::Command;
use zeroize::Zeroize;

use crate::crypto::keys::Vkek;
use crate::store::sqlite;

// ── helpers ──────────────────────────────────────────────────────

/// Persistent handle we use for the primary storage key.
/// Override with `VAULT_TPM_HANDLE` environment variable if another app uses this handle.
/// Range 0x81000000–0x810000FF is typically available for user applications.
pub const DEFAULT_TPM_HANDLE: &str = "0x81000100";

/// Return the configured TPM persistent handle.
fn tpm_handle() -> String {
    std::env::var("VAULT_TPM_HANDLE").unwrap_or_else(|_| DEFAULT_TPM_HANDLE.to_string())
}

/// Check whether a usable TPM 2.0 resource manager device exists.
pub fn tpm_available() -> bool {
    std::path::Path::new("/dev/tpmrm0").exists()
}

fn run_tpm2(args: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new(args[0])
        .args(&args[1..])
        .output()
        .with_context(|| format!("failed to run {} — is tpm2-tools installed?", args[0]))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let hint = if stderr.contains("tcti") || stderr.contains("TCTI") {
            " (hint: check that tpm2-abrmd is running or /dev/tpmrm0 is accessible)"
        } else if stderr.contains("auth") || stderr.contains("AUTH") {
            " (hint: TPM authorization failed — was the owner password changed?)"
        } else {
            ""
        };
        anyhow::bail!("{} failed: {}{}", args[0], stderr.trim(), hint);
    }

    Ok(output.stdout)
}

#[allow(dead_code)]
fn run_tpm2_with_stdin(args: &[&str], stdin_data: &[u8]) -> Result<Vec<u8>> {
    use std::io::Write;
    let mut child = Command::new(args[0])
        .args(&args[1..])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to spawn {}", args[0]))?;

    child
        .stdin
        .as_mut()
        .context("failed to open tpm2 tool stdin")?
        .write_all(stdin_data)
        .context("write to tpm2 tool stdin")?;

    let output = child.wait_with_output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("{} failed: {}", args[0], stderr.trim());
    }
    Ok(output.stdout)
}

// ── RAII temp dir guard ──────────────────────────────────────────

/// Secure temporary directory that is cleaned up on drop, including zeroizing
/// any plaintext data files written inside it.
struct SecureTpmTempDir {
    dir: tempfile::TempDir,
    /// Paths to files whose content must be zeroized before removal.
    sensitive_files: Vec<std::path::PathBuf>,
}

impl SecureTpmTempDir {
    fn new() -> Result<Self> {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::Builder::new()
            .prefix("vault-tpm-")
            .tempdir()
            .context("failed to create secure temp dir for TPM operation")?;
        // Enforce 0700 on the temp directory.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
        Ok(Self {
            dir,
            sensitive_files: Vec::new(),
        })
    }

    /// Write data to a file inside the temp dir with mode 0600.
    fn write_file(
        &mut self,
        name: &str,
        data: &[u8],
        sensitive: bool,
    ) -> Result<std::path::PathBuf> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let path = self.dir.path().join(name);
        let mut f = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("write temp file {}", name))?;
        f.write_all(data)?;
        f.sync_all()?;
        if sensitive {
            self.sensitive_files.push(path.clone());
        }
        Ok(path)
    }

    fn path(&self) -> &std::path::Path {
        self.dir.path()
    }
}

impl Drop for SecureTpmTempDir {
    fn drop(&mut self) {
        // Zeroize sensitive files before temp dir cleanup removes them.
        for path in &self.sensitive_files {
            if let Ok(len) = std::fs::metadata(path).map(|m| m.len()) {
                if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(path) {
                    use std::io::Write;
                    let zeros = vec![0u8; len as usize];
                    let _ = f.write_all(&zeros);
                    let _ = f.sync_all();
                }
            }
        }
        // TempDir::drop handles recursive removal.
    }
}

// ── ensure primary key ───────────────────────────────────────────

/// Make sure a persistent primary storage key exists at `PRIMARY_HANDLE`.
/// If it already exists we silently succeed.
fn ensure_primary_key() -> Result<()> {
    let handle = tpm_handle();

    // Try to read the existing persistent handle
    let check = Command::new("tpm2_readpublic")
        .args(["-c", &handle])
        .output();

    if let Ok(ref o) = check {
        if o.status.success() {
            return Ok(()); // already provisioned
        }
    }

    // Create a transient primary in the owner hierarchy — use secure temp dir.
    let tmp = SecureTpmTempDir::new()?;
    let tmp_ctx = tmp.path().join("primary.ctx");
    let tmp_ctx_str = tmp_ctx.display().to_string();

    run_tpm2(&[
        "tpm2_createprimary",
        "-C",
        "o",
        "-g",
        "sha256",
        "-G",
        "rsa2048",
        "-c",
        &tmp_ctx_str,
    ])
    .context("tpm2_createprimary failed – is the TPM accessible and tpm2-abrmd running?")?;

    // Check if handle is already taken before evicting
    let existing = Command::new("tpm2_readpublic")
        .args(["-c", &handle])
        .output();
    if let Ok(ref o) = existing {
        if o.status.success() {
            let _ = run_tpm2(&["tpm2_evictcontrol", "-C", "o", "-c", &handle]);
        }
    }

    // Persist it
    run_tpm2(&[
        "tpm2_evictcontrol",
        "-C",
        "o",
        "-c",
        &tmp_ctx_str,
        &handle,
    ])
    .with_context(|| format!(
        "tpm2_evictcontrol failed — handle {} may already be in use. \
         Set VAULT_TPM_HANDLE to use a different persistent handle.",
        handle
    ))?;

    // tmp drops here, cleaning up
    Ok(())
}

// ── seal / unseal ────────────────────────────────────────────────

/// Seal `plaintext` under the TPM primary key.  Returns the sealed blob.
fn tpm_seal(plaintext: &[u8]) -> Result<Vec<u8>> {
    ensure_primary_key()?;
    let handle = tpm_handle();

    // Use secure temp dir with RAII cleanup.
    let mut tmp = SecureTpmTempDir::new()?;

    let data_path = tmp.write_file("seal-data", plaintext, true)?;
    let pub_path = tmp.path().join("seal.pub");
    let priv_path = tmp.path().join("seal.priv");

    let data_str = data_path.display().to_string();
    let pub_str = pub_path.display().to_string();
    let priv_str = priv_path.display().to_string();

    // Create a sealing object under the primary
    run_tpm2(&[
        "tpm2_create",
        "-C",
        &handle,
        "-i",
        &data_str,
        "-u",
        &pub_str,
        "-r",
        &priv_str,
    ])
    .context("tpm2_create (seal) failed — the TPM may be out of transient object slots")?;

    // Read the pub + priv blobs and concatenate with a length prefix
    let pub_blob = std::fs::read(&pub_path).context("read seal pub")?;
    let priv_blob = std::fs::read(&priv_path).context("read seal priv")?;

    // Pack: [pub_len: u32 LE][pub_blob][priv_blob]
    let mut packed = Vec::with_capacity(4 + pub_blob.len() + priv_blob.len());
    packed.extend_from_slice(&(pub_blob.len() as u32).to_le_bytes());
    packed.extend_from_slice(&pub_blob);
    packed.extend_from_slice(&priv_blob);

    // tmp drops here → zeroizes seal-data, removes dir
    Ok(packed)
}

/// Unseal a blob previously sealed with `tpm_seal`.
fn tpm_unseal(packed: &[u8]) -> Result<Vec<u8>> {
    if packed.len() < 4 {
        anyhow::bail!("invalid TPM sealed blob (too short)");
    }

    let pub_len = u32::from_le_bytes(packed[..4].try_into()
        .context("invalid TPM sealed blob header")?) as usize;
    if packed.len() < 4 + pub_len {
        anyhow::bail!("invalid TPM sealed blob (truncated)");
    }

    let pub_blob = &packed[4..4 + pub_len];
    let priv_blob = &packed[4 + pub_len..];

    let mut tmp = SecureTpmTempDir::new()?;
    let handle = tpm_handle();
    let pub_path = tmp.write_file("unseal.pub", pub_blob, false)?;
    let priv_path = tmp.write_file("unseal.priv", priv_blob, false)?;
    let ctx_path = tmp.path().join("unseal.ctx");

    let pub_str = pub_path.display().to_string();
    let priv_str = priv_path.display().to_string();
    let ctx_str = ctx_path.display().to_string();

    // Load the sealed object
    run_tpm2(&[
        "tpm2_load",
        "-C",
        &handle,
        "-u",
        &pub_str,
        "-r",
        &priv_str,
        "-c",
        &ctx_str,
    ])
    .context("tpm2_load failed — was the sealed blob created with a different TPM or primary key?")?;

    // Unseal
    let plaintext = run_tpm2(&["tpm2_unseal", "-c", &ctx_str])
        .context("tpm2_unseal failed — was the VKEK sealed on a different machine or TPM?")?;

    // tmp drops here, cleaning up all temp files
    Ok(plaintext)
}

// ── public API (called from slot.rs) ─────────────────────────────

/// Create a TPM2 auth slot – seals the VKEK to the TPM.
pub fn create_tpm_slot(conn: &rusqlite::Connection, vkek: &Vkek) -> Result<i64> {
    if !tpm_available() {
        anyhow::bail!("TPM 2.0 not found. Is tpm2-abrmd or /dev/tpmrm0 accessible?");
    }

    let sealed = tpm_seal(vkek.as_bytes()).context("failed to seal VKEK to TPM")?;

    let handle = tpm_handle();
    let slot_id = sqlite::insert_auth_slot(
        conn,
        sqlite::SlotKind::Tpm,
        &sealed,
        None,
        Some(&format!(r#"{{"method":"tpm2-tools","handle":"{}"}}"#, handle)),
    )?;

    Ok(slot_id)
}

/// Unwrap VKEK from a TPM2 auth slot.
pub fn unwrap_tpm_slot(slot: &sqlite::AuthSlotRow) -> Result<Vkek> {
    if !tpm_available() {
        anyhow::bail!("TPM 2.0 not found. Is tpm2-abrmd or /dev/tpmrm0 accessible?");
    }

    let mut plaintext = tpm_unseal(&slot.wrapped_vkek).context("failed to unseal VKEK from TPM")?;

    if plaintext.len() != 32 {
        plaintext.zeroize();
        anyhow::bail!("unsealed VKEK has invalid length ({})", plaintext.len());
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&plaintext);
    plaintext.zeroize();
    Ok(Vkek::from_bytes(key))
}
