//! CLI secrets vault with envelope encryption.

use vault_lib as lib;
use lib::{auth, store, vault};
#[cfg(unix)]
use lib::agent;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::io::Read;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "vault", version, about = "A local-first CLI secrets vault")]
struct Cli {
    /// Path to the vault database
    #[arg(long, global = true)]
    db: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new vault
    Init {
        #[cfg(target_os = "linux")]
        #[arg(long)]
        trust_local: bool,
        #[cfg(target_os = "linux")]
        #[arg(long)]
        tpm: bool,
        #[cfg(target_os = "macos")]
        #[arg(long)]
        keychain: bool,
        #[cfg(target_os = "windows")]
        #[arg(long)]
        dpapi: bool,
    },
    /// Store a secret
    Set {
        name: String,
        value: Option<String>,
        #[arg(long)]
        stdin: bool,
    },
    /// Retrieve a secret
    Get {
        name: String,
    },
    /// List all secret names
    List,
    /// Delete a secret
    Delete {
        name: String,
    },
    /// Lock the vault (stop agent, zeroize keys)
    #[cfg(unix)]
    Lock,
    /// Unlock the vault (start agent, authenticate)
    #[cfg(unix)]
    Unlock {
        #[arg(long)]
        ttl: Option<u64>,
    },
    /// Run the vault agent daemon
    #[cfg(unix)]
    Agent {
        #[arg(long, default_value = "900")]
        ttl: u64,
    },
    /// Run a command with secrets injected as environment variables
    Exec {
        #[arg(long = "env", short = 'e')]
        envs: Vec<String>,
        /// Inject all secrets as environment variables
        #[arg(long)]
        all: bool,
        #[arg(long)]
        yes: bool,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Show vault status
    Status,
    /// Run security diagnostics
    Doctor,
    /// Export all secrets to an encrypted file
    Export {
        /// Output file path (writes to stdout if omitted)
        file: Option<String>,
        /// Read export passphrase from stdin
        #[arg(long)]
        stdin: bool,
    },
    /// Import secrets from an encrypted export file
    Import {
        file: String,
        /// Read export passphrase from stdin
        #[arg(long)]
        stdin: bool,
        #[arg(long)]
        force: bool,
    },
    /// Manage authentication slots
    Auth {
        #[command(subcommand)]
        command: AuthCommands,
    },
}

#[derive(Subcommand)]
enum AuthCommands {
    /// Add a new authentication slot
    Add {
        /// Slot type: "passphrase" or "trust-local"
        slot_type: String,
        /// Allow convenience-only trust-local auth when no passphrase slot exists
        #[arg(long)]
        force: bool,
    },
    /// List all authentication slots
    List,
    /// Remove an authentication slot
    Remove {
        slot_id: i64,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let db_path = cli
        .db
        .map(std::path::PathBuf::from)
        .unwrap_or_else(store::sqlite::default_db_path);

    match cli.command {
        Commands::Init {
            #[cfg(target_os = "linux")]
            trust_local,
            #[cfg(target_os = "linux")]
            tpm,
            #[cfg(target_os = "macos")]
            keychain,
            #[cfg(target_os = "windows")]
            dpapi,
        } => {
            #[cfg(not(target_os = "linux"))]
            let trust_local = false;
            #[cfg(not(target_os = "linux"))]
            let tpm = false;
            #[cfg(not(target_os = "macos"))]
            let keychain = false;
            #[cfg(not(target_os = "windows"))]
            let dpapi = false;

            let auth = if tpm {
                vault::InitAuth::Tpm
            } else if keychain {
                vault::InitAuth::Keychain
            } else if dpapi {
                vault::InitAuth::Dpapi
            } else if trust_local {
                vault::InitAuth::TrustLocal
            } else {
                vault::InitAuth::Passphrase
            };
            cmd_init(&db_path, auth)
        }
        Commands::Set {
            name,
            value,
            stdin,
        } => cmd_set(&db_path, &name, value, stdin),
        Commands::Get { name } => cmd_get(&db_path, &name),
        Commands::List => cmd_list(&db_path),
        Commands::Delete { name } => cmd_delete(&db_path, &name),
        #[cfg(unix)]
        Commands::Lock => cmd_lock(&db_path),
        #[cfg(unix)]
        Commands::Unlock { ttl } => cmd_unlock(&db_path, ttl),
        #[cfg(unix)]
        Commands::Agent { ttl } => cmd_agent(&db_path, ttl),
        Commands::Exec {
            envs,
            all,
            yes,
            command,
        } => cmd_exec(&db_path, &envs, &command, yes, all),
        Commands::Status => cmd_status(&db_path),
        Commands::Doctor => cmd_doctor(&db_path),
        Commands::Export { file, stdin } => cmd_export(&db_path, file, stdin),
        Commands::Import {
            file,
            stdin,
            force,
        } => cmd_import(&db_path, &file, stdin, force),
        Commands::Auth { command: auth_cmd } => match auth_cmd {
            AuthCommands::Add { slot_type, force } => cmd_auth_add(&db_path, &slot_type, force),
            AuthCommands::List => cmd_auth_list(&db_path),
            AuthCommands::Remove { slot_id } => cmd_auth_remove(&db_path, slot_id),
        },
    }
}

fn open_db(path: &std::path::Path) -> Result<rusqlite::Connection> {
    let conn = store::sqlite::open_db(path)?;
    store::sqlite::init_schema(&conn).context("failed to initialize schema")?;
    Ok(conn)
}

#[cfg(unix)]
fn current_vault_id(conn: &rusqlite::Connection) -> Option<String> {
    store::sqlite::get_meta(conn, "vault_id")
        .ok()
        .flatten()
        .and_then(|v| String::from_utf8(v).ok())
}

fn cmd_init(db_path: &std::path::Path, auth: vault::InitAuth) -> Result<()> {
    let conn = store::sqlite::open_db(db_path)?;
    vault::init_vault(&conn, auth)?;
    eprintln!("  Database: {}", db_path.display());
    Ok(())
}

fn cmd_set(
    db_path: &std::path::Path,
    name: &str,
    value: Option<String>,
    stdin: bool,
) -> Result<()> {
    vault::validate_secret_name(name)?;
    let conn = open_db(db_path)?;
    let vkek = vault::unlock_vault(&conn)?;

    if stdin && value.is_some() {
        eprintln!("Error: cannot use both inline value and --stdin");
        std::process::exit(1);
    }

    let secret_value = if stdin {
        let mut buf = Zeroizing::new(Vec::new());
        std::io::stdin().read_to_end(&mut buf)?;
        if buf.last() == Some(&b'\n') {
            buf.pop();
        }
        buf
    } else if let Some(v) = value {
        Zeroizing::new(v.into_bytes())
    } else {
        let v = rpassword::prompt_password("Enter secret value: ")
            .context("failed to read secret value")?;
        Zeroizing::new(v.into_bytes())
    };

    vault::validate_secret_value(secret_value.as_slice())?;
    vault::set_secret(&conn, &vkek, name, secret_value.as_slice())?;
    eprintln!("✓ Secret '{}' stored", name);
    Ok(())
}

fn cmd_get(db_path: &std::path::Path, name: &str) -> Result<()> {
    vault::validate_secret_name(name)?;
    let conn = open_db(db_path)?;
    let vkek = vault::unlock_vault(&conn)?;
    let value = Zeroizing::new(vault::get_secret(&conn, &vkek, name)?);

    use std::io::Write;
    std::io::stdout().write_all(value.as_slice())?;
    if atty_check() {
        println!();
    }
    Ok(())
}

fn cmd_list(db_path: &std::path::Path) -> Result<()> {
    let conn = open_db(db_path)?;
    let vkek = vault::unlock_vault(&conn)?;
    let names = vault::list_secrets(&conn, &vkek)?;

    if names.is_empty() {
        eprintln!("No secrets stored");
    } else {
        for name in &names {
            println!("{}", name);
        }
    }
    Ok(())
}

fn cmd_delete(db_path: &std::path::Path, name: &str) -> Result<()> {
    vault::validate_secret_name(name)?;
    let conn = open_db(db_path)?;
    let vkek = vault::unlock_vault(&conn)?;

    if vault::delete_secret(&conn, &vkek, name)? {
        eprintln!("✓ Secret '{}' deleted", name);
    } else {
        anyhow::bail!("secret '{}' not found", name);
    }
    Ok(())
}

#[cfg(unix)]
fn cmd_lock(db_path: &std::path::Path) -> Result<()> {
    let conn = open_db(db_path)?;
    let vault_id = current_vault_id(&conn);
    if agent::client::is_agent_running_for_vault(vault_id.as_deref()) {
        agent::client::lock_for_vault(vault_id.as_deref())?;
        eprintln!("✓ Vault locked");
    } else {
        eprintln!("Agent is not running (vault is already locked)");
    }
    Ok(())
}

#[cfg(unix)]
fn cmd_unlock(db_path: &std::path::Path, ttl: Option<u64>) -> Result<()> {
    let conn = open_db(db_path)?;
    let vault_id =
        current_vault_id(&conn).ok_or_else(|| anyhow::anyhow!("vault is not initialized"))?;

    if !agent::client::is_agent_running_for_vault(Some(&vault_id)) {
        let ttl_val = ttl.unwrap_or(900);
        let db_str = db_path.display().to_string();
        let exe = std::env::current_exe()?;
        let mut cmd = std::process::Command::new(exe);
        cmd.arg("agent").arg("--ttl").arg(ttl_val.to_string());
        if db_path != store::sqlite::default_db_path() {
            cmd.arg("--db").arg(&db_str);
        }
        cmd.stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped());
        let _child = cmd.spawn().context("failed to start agent")?;
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    let vkek = vault::unlock_vault(&conn)?;
    if agent::client::is_agent_running_for_vault(Some(&vault_id)) {
        agent::client::store_vkek_for_vault(&vkek, Some(&vault_id))?;
        eprintln!("✓ Vault unlocked (agent running)");
    } else {
        eprintln!("✓ Vault unlocked (no agent — keys will not persist)");
    }
    Ok(())
}

#[cfg(unix)]
fn cmd_agent(db_path: &std::path::Path, ttl: u64) -> Result<()> {
    let conn = open_db(db_path)?;
    let vault_id = current_vault_id(&conn);
    agent::server::run_agent(None, Some(ttl), vault_id)
}

fn cmd_exec(
    db_path: &std::path::Path,
    envs: &[String],
    command: &[String],
    yes: bool,
    all: bool,
) -> Result<()> {
    if command.is_empty() {
        anyhow::bail!("no command specified");
    }

    if envs.is_empty() && !all {
        anyhow::bail!("specify secrets with -e NAME=secret or use --all to inject every secret");
    }

    // Validate env var name: alphanumeric + underscore only
    fn validate_env_name(name: &str) -> Result<()> {
        if name.is_empty() {
            anyhow::bail!("environment variable name cannot be empty");
        }
        if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            anyhow::bail!(
                "invalid environment variable name '{}': only alphanumeric and underscore allowed",
                name
            );
        }
        Ok(())
    }

    let conn = open_db(db_path)?;
    let vkek = vault::unlock_vault(&conn)?;
    let mut cmd = std::process::Command::new(&command[0]);
    cmd.args(&command[1..]);

    for env_spec in envs {
        let (env_name, secret_name) = env_spec.split_once('=').ok_or_else(|| {
            anyhow::anyhow!("invalid env spec '{}': use NAME=secret-name", env_spec)
        })?;
        validate_env_name(env_name)?;
        vault::validate_secret_name(secret_name)?;
        let value = Zeroizing::new(vault::get_secret(&conn, &vkek, secret_name)?);
        let value_str =
            String::from_utf8(value.to_vec()).context("secret value is not valid UTF-8")?;
        cmd.env(env_name, &value_str);
    }

    if all {
        let names = vault::list_secrets(&conn, &vkek)?;
        if !yes && !names.is_empty() {
            eprintln!(
                "⚠ Injecting all {} secrets as environment variables. ",
                names.len()
            );
        }

        // Build env-name → secret-names mapping for collision detection
        let mut env_map: HashMap<String, Vec<String>> = HashMap::new();
        for name in &names {
            let env_name = name.replace(['/', '-', '.'], "_").to_uppercase();
            env_map.entry(env_name).or_default().push(name.clone());
        }

        // Check for collisions (including dash/dot → underscore transforms)
        let collisions: Vec<_> = env_map.iter()
            .filter(|(_, secrets)| secrets.len() > 1)
            .collect();
        if !collisions.is_empty() {
            for (env_name, secrets) in &collisions {
                eprintln!(
                    "Error: env var collision: '{}' and '{}' both map to '{}'",
                    secrets[0], secrets[1], env_name
                );
            }
            std::process::exit(1);
        }

        for name in &names {
            let value = Zeroizing::new(vault::get_secret(&conn, &vkek, name)?);
            let value_str =
                String::from_utf8(value.to_vec()).context("secret value is not valid UTF-8")?;
            let env_name = name.replace(['/', '-', '.'], "_").to_uppercase();
            // Warn on stderr when a name transformation occurs
            if env_name != *name {
                eprintln!("Note: '{}' → {}", name, env_name);
            }
            validate_env_name(&env_name)?;
            cmd.env(&env_name, &value_str);
        }
    }

    let status = cmd.status().context("failed to execute command")?;
    std::process::exit(status.code().unwrap_or(1));
}

fn cmd_status(db_path: &std::path::Path) -> Result<()> {
    let conn = open_db(db_path)?;
    let status = vault::vault_status(&conn, db_path)?;

    if !status.initialized {
        println!("Vault: not initialized");
        println!("  Run 'vault init' to create a new vault");
        return Ok(());
    }

    println!("Vault Status");
    println!("─────────────────────────────────");
    if let Some(ref id) = status.vault_id {
        println!("  Vault ID:      {}", id);
    }
    println!("  Database:      {}", status.db_path);
    if let Some(ref v) = status.schema_version {
        println!("  Schema:        v{}", v);
    }
    if let Some(ref c) = status.cipher_suite {
        println!("  Cipher suite:  {}", c);
    }
    if let Some(ref t) = status.created_at {
        println!("  Created:       {}", t);
    }
    println!("  Secrets:       {}", status.secret_count);
    println!(
        "  Auth slots:    {} ({:?})",
        status.auth_slot_count, status.auth_slot_types
    );

    match status.agent_status {
        vault::AgentStatus::NotRunning => println!("  Agent:         not running"),
        vault::AgentStatus::Locked => println!("  Agent:         running (locked)"),
        vault::AgentStatus::Unlocked { ttl_remaining } => {
            if let Some(ttl) = ttl_remaining {
                println!("  Agent:         running (unlocked, {}s remaining)", ttl);
            } else {
                println!("  Agent:         running (unlocked)");
            }
        }
    }
    Ok(())
}

fn cmd_doctor(db_path: &std::path::Path) -> Result<()> {
    let conn = open_db(db_path)?;
    let items = vault::doctor(&conn, db_path)?;

    println!("Vault Security Diagnostics");
    println!("══════════════════════════════════");
    for item in &items {
        println!("  {} {}: {}", item.status, item.name, item.message);
    }
    Ok(())
}

/// Read a passphrase line from stdin (for --stdin mode).
fn read_passphrase_from_stdin() -> Result<Vec<u8>> {
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)
        .context("failed to read passphrase from stdin")?;
    // Strip trailing newline
    if line.ends_with('\n') {
        line.pop();
        if line.ends_with('\r') {
            line.pop();
        }
    }
    if line.is_empty() {
        anyhow::bail!("export passphrase cannot be empty");
    }
    Ok(line.into_bytes())
}

fn cmd_export(db_path: &std::path::Path, file: Option<String>, stdin: bool) -> Result<()> {
    let conn = open_db(db_path)?;
    let vkek = vault::unlock_vault(&conn)?;

    let export_passphrase = if stdin {
        Zeroizing::new(read_passphrase_from_stdin()?)
    } else {
        Zeroizing::new(auth::passphrase::prompt_export_passphrase(true)?)
    };
    let output = vault::export_vault(&conn, &vkek, export_passphrase.as_slice())?;

    if let Some(path) = file {
        std::fs::write(&path, &output)
            .with_context(|| format!("failed to write export to {}", path))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).ok();
        }
        eprintln!("✓ Vault exported to {}", path);
    } else {
        use std::io::Write;
        std::io::stdout().write_all(output.as_bytes())?;
        std::io::stdout().write_all(b"\n")?;
    }
    Ok(())
}

fn cmd_import(db_path: &std::path::Path, file: &str, stdin: bool, force: bool) -> Result<()> {
    let conn = open_db(db_path)?;
    let vkek = vault::unlock_vault(&conn)?;

    let metadata =
        std::fs::metadata(file).with_context(|| format!("failed to stat export file: {}", file))?;
    vault::validate_import_size(metadata.len() as usize)?;
    let export_data = std::fs::read_to_string(file)
        .with_context(|| format!("failed to read export file: {}", file))?;

    let export_passphrase = if stdin {
        Zeroizing::new(read_passphrase_from_stdin()?)
    } else {
        Zeroizing::new(auth::passphrase::prompt_export_passphrase(false)?)
    };
    let imported = vault::import_vault(
        &conn,
        &vkek,
        &export_data,
        export_passphrase.as_slice(),
        force,
    )?;
    eprintln!("✓ Imported {} secret(s)", imported);
    Ok(())
}

fn cmd_auth_add(
    db_path: &std::path::Path,
    slot_type: &str,
    force: bool,
) -> Result<()> {
    let conn = open_db(db_path)?;
    let vkek = vault::unlock_vault(&conn)?;
    let vault_id = vault::get_vault_id(&conn)?;

    match slot_type {
        "passphrase" => {
            let slot_id = vault::add_passphrase_slot(&conn, &vkek)?;
            eprintln!("✓ Passphrase auth slot added (ID: {})", slot_id);
        }
        #[cfg(target_os = "linux")]
        "trust-local" => {
            let slot_id = vault::add_trust_local_slot(&conn, &vkek, &vault_id, force)?;
            eprintln!("✓ Trust-local auth slot added (ID: {})", slot_id);
        }
        #[cfg(target_os = "linux")]
        "tpm" | "tpm2" => {
            let slot_id = vault::add_tpm_slot(&conn, &vkek)?;
            eprintln!("✓ TPM 2.0 auth slot added (ID: {})", slot_id);
        }
        #[cfg(target_os = "macos")]
        "keychain" => {
            let slot_id = vault::add_keychain_slot(&conn, &vkek)?;
            eprintln!("✓ Keychain auth slot added (ID: {})", slot_id);
        }
        #[cfg(target_os = "windows")]
        "dpapi" => {
            let slot_id = vault::add_dpapi_slot(&conn, &vkek)?;
            eprintln!("✓ DPAPI auth slot added (ID: {})", slot_id);
        }
        _ => {
            let mut supported = vec!["passphrase"];
            #[cfg(target_os = "linux")]
            {
                supported.push("trust-local");
                supported.push("tpm");
            }
            #[cfg(target_os = "macos")]
            supported.push("keychain");
            #[cfg(target_os = "windows")]
            supported.push("dpapi");
            anyhow::bail!(
                "unknown slot type '{}'. Supported types: {}",
                slot_type,
                supported.join(", ")
            );
        }
    }
    Ok(())
}

fn cmd_auth_list(db_path: &std::path::Path) -> Result<()> {
    let conn = open_db(db_path)?;
    let slots = vault::list_auth_slots(&conn)?;

    if slots.is_empty() {
        eprintln!("No auth slots configured");
    } else {
        println!("Auth Slots");
        println!("──────────────────────────────────────────");
        for slot in &slots {
            println!(
                "  [{}] type={:<15} created={}",
                slot.id, slot.slot_type, slot.created_at
            );
        }
    }
    Ok(())
}

fn cmd_auth_remove(db_path: &std::path::Path, slot_id: i64) -> Result<()> {
    let conn = open_db(db_path)?;
    let _vkek = vault::unlock_vault(&conn)?;
    vault::remove_auth_slot(&conn, slot_id)?;
    eprintln!("✓ Auth slot {} removed", slot_id);
    Ok(())
}

fn atty_check() -> bool {
    #[cfg(unix)]
    {
        nix::unistd::isatty(1).unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        false
    }
}
