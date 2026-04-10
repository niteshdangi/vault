use anyhow::Result;
use rusqlite::Connection;
use std::path::Path;

use crate::store::sqlite;

/// Run security diagnostics.
pub fn doctor(conn: &Connection, db_path: &Path) -> Result<Vec<DiagnosticItem>> {
    let mut items = Vec::new();

    let initialized = sqlite::is_initialized(conn)?;
    items.push(DiagnosticItem {
        name: "Vault initialized".to_string(),
        status: if initialized {
            DiagStatus::Ok
        } else {
            DiagStatus::Error
        },
        message: if initialized {
            "Vault database is initialized".to_string()
        } else {
            "Vault is not initialized. Run 'vault init'".to_string()
        },
    });

    if !initialized {
        return Ok(items);
    }

    let slots = sqlite::get_all_auth_slots(conn)?;
    items.push(DiagnosticItem {
        name: "Auth slots".to_string(),
        status: if slots.is_empty() {
            DiagStatus::Error
        } else {
            DiagStatus::Ok
        },
        message: format!("{} auth slot(s) configured", slots.len()),
    });

    let has_passphrase = slots.iter().any(|s| s.kind == sqlite::SlotKind::Passphrase);
    let has_trust_local = slots.iter().any(|s| s.kind == sqlite::SlotKind::TrustLocal);
    if has_trust_local && !has_passphrase {
        items.push(DiagnosticItem {
            name: "Auth strength".to_string(),
            status: DiagStatus::Warning,
            message: "Only trust-local auth configured. Consider adding a passphrase slot for stronger security".to_string(),
        });
    }

    let db_path_buf = db_path.to_path_buf();
    if db_path_buf.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let metadata = std::fs::metadata(&db_path_buf)?;
            let mode = metadata.mode() & 0o777;
            items.push(DiagnosticItem {
                name: "DB file permissions".to_string(),
                status: if mode <= 0o600 {
                    DiagStatus::Ok
                } else {
                    DiagStatus::Warning
                },
                message: format!("Permissions: {:o} (recommended: 600)", mode),
            });
        }
    }

    #[cfg(unix)]
    {
        use super::get_vault_id;
        let agent_running = if let Ok(vault_id) = get_vault_id(conn) {
            crate::agent::client::is_agent_running_for_vault(Some(&vault_id))
        } else {
            crate::agent::client::is_agent_running()
        };
        items.push(DiagnosticItem {
            name: "Agent status".to_string(),
            status: if agent_running {
                DiagStatus::Ok
            } else {
                DiagStatus::Info
            },
            message: if agent_running {
                "Agent is running".to_string()
            } else {
                "Agent is not running. Unlock operations will require re-authentication each time"
                    .to_string()
            },
        });
    }

    #[cfg(target_os = "linux")]
    {
        items.push(DiagnosticItem {
            name: "Core dumps".to_string(),
            status: DiagStatus::Info,
            message: "Agent sets PR_SET_DUMPABLE=0 when running".to_string(),
        });

        let tpm_available = std::path::Path::new("/dev/tpmrm0").exists();
        items.push(DiagnosticItem {
            name: "TPM 2.0".to_string(),
            status: if tpm_available {
                DiagStatus::Ok
            } else {
                DiagStatus::Info
            },
            message: if tpm_available {
                "/dev/tpmrm0 found — TPM 2.0 auth available".to_string()
            } else {
                "TPM 2.0 not found. Is tpm2-abrmd or /dev/tpmrm0 accessible?".to_string()
            },
        });

        let tpm2_tools = std::process::Command::new("tpm2_getcap")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        items.push(DiagnosticItem {
            name: "tpm2-tools".to_string(),
            status: if tpm2_tools {
                DiagStatus::Ok
            } else {
                DiagStatus::Info
            },
            message: if tpm2_tools {
                "tpm2-tools installed".to_string()
            } else {
                "tpm2-tools not found in PATH — needed for TPM auth".to_string()
            },
        });
    }

    let count = sqlite::count_secrets(conn)?;
    items.push(DiagnosticItem {
        name: "Secrets stored".to_string(),
        status: DiagStatus::Info,
        message: format!("{} secret(s)", count),
    });

    Ok(items)
}

#[derive(Debug)]
pub struct DiagnosticItem {
    pub name: String,
    pub status: DiagStatus,
    pub message: String,
}

#[derive(Debug)]
pub enum DiagStatus {
    Ok,
    Warning,
    Error,
    Info,
}

impl std::fmt::Display for DiagStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiagStatus::Ok => write!(f, "✓"),
            DiagStatus::Warning => write!(f, "⚠"),
            DiagStatus::Error => write!(f, "✗"),
            DiagStatus::Info => write!(f, "ℹ"),
        }
    }
}
