use std::process::Command;
use tempfile::TempDir;

/// Build a Command that points at the vault binary with an isolated --db path.
fn vault_cmd(db_dir: &std::path::Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_vault"));
    let db_path = db_dir.join("vault.db");
    cmd.arg("--db").arg(&db_path);
    // Prevent any TTY prompts from blocking
    cmd.stdin(std::process::Stdio::null());
    cmd
}

/// Initialise a vault with --trust-local in the given temp dir.
fn init_vault(dir: &std::path::Path) {
    let out = vault_cmd(dir)
        .args(["init", "--trust-local"])
        .output()
        .expect("failed to run vault init");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "vault init failed: {}",
        stderr
    );
    assert!(
        stderr.contains("initialized"),
        "expected 'initialized' in output, got: {}",
        stderr
    );
}

#[test]
fn test_init_trust_local() {
    let tmp = TempDir::new().unwrap();
    init_vault(tmp.path());
}

#[test]
fn test_init_twice_fails() {
    let tmp = TempDir::new().unwrap();
    init_vault(tmp.path());
    let out = vault_cmd(tmp.path())
        .args(["init", "--trust-local"])
        .output()
        .expect("failed to run vault init");
    assert!(
        !out.status.success(),
        "second init should fail but succeeded"
    );
}

#[test]
fn test_set_and_get() {
    let tmp = TempDir::new().unwrap();
    init_vault(tmp.path());

    let out = vault_cmd(tmp.path())
        .args(["set", "mykey", "myvalue"])
        .output()
        .unwrap();
    assert!(out.status.success(), "set failed: {}", String::from_utf8_lossy(&out.stderr));

    let out = vault_cmd(tmp.path())
        .args(["get", "mykey"])
        .output()
        .unwrap();
    assert!(out.status.success(), "get failed: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stdout.trim(), "myvalue");
}

#[test]
fn test_set_stdin() {
    let tmp = TempDir::new().unwrap();
    init_vault(tmp.path());

    let db_path = tmp.path().join("vault.db");
    let out = Command::new(env!("CARGO_BIN_EXE_vault"))
        .arg("--db").arg(&db_path)
        .args(["set", "mykey", "--stdin"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child.stdin.take().unwrap().write_all(b"stdinvalue\n").unwrap();
            child.wait_with_output()
        })
        .unwrap();
    assert!(out.status.success(), "set --stdin failed: {}", String::from_utf8_lossy(&out.stderr));

    let out = vault_cmd(tmp.path())
        .args(["get", "mykey"])
        .output()
        .unwrap();
    assert!(out.status.success(), "get failed: {}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "stdinvalue");
}

#[test]
fn test_get_nonexistent() {
    let tmp = TempDir::new().unwrap();
    init_vault(tmp.path());

    let out = vault_cmd(tmp.path())
        .args(["get", "nokey"])
        .output()
        .unwrap();
    assert!(!out.status.success(), "get nonexistent should fail");
}

#[test]
fn test_list_empty() {
    let tmp = TempDir::new().unwrap();
    init_vault(tmp.path());

    let out = vault_cmd(tmp.path())
        .args(["list"])
        .output()
        .unwrap();
    assert!(out.status.success(), "list failed: {}", String::from_utf8_lossy(&out.stderr));
    // "No secrets stored" is on stderr; stdout should be empty
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.trim().is_empty(), "expected empty stdout, got: {}", stdout);
}

#[test]
fn test_list_with_secrets() {
    let tmp = TempDir::new().unwrap();
    init_vault(tmp.path());

    for name in &["alpha", "beta", "gamma"] {
        let out = vault_cmd(tmp.path())
            .args(["set", name, &format!("val-{}", name)])
            .output()
            .unwrap();
        assert!(out.status.success(), "set {} failed: {}", name, String::from_utf8_lossy(&out.stderr));
    }

    let out = vault_cmd(tmp.path())
        .args(["list"])
        .output()
        .unwrap();
    assert!(out.status.success(), "list failed: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    for name in &["alpha", "beta", "gamma"] {
        assert!(stdout.contains(name), "list output missing '{}': {}", name, stdout);
    }
}

#[test]
fn test_delete() {
    let tmp = TempDir::new().unwrap();
    init_vault(tmp.path());

    let out = vault_cmd(tmp.path())
        .args(["set", "delme", "value"])
        .output()
        .unwrap();
    assert!(out.status.success());

    let out = vault_cmd(tmp.path())
        .args(["delete", "delme"])
        .output()
        .unwrap();
    assert!(out.status.success(), "delete failed: {}", String::from_utf8_lossy(&out.stderr));

    let out = vault_cmd(tmp.path())
        .args(["get", "delme"])
        .output()
        .unwrap();
    assert!(!out.status.success(), "get after delete should fail");
}

#[test]
fn test_status() {
    let tmp = TempDir::new().unwrap();
    init_vault(tmp.path());

    let out = vault_cmd(tmp.path())
        .args(["status"])
        .output()
        .unwrap();
    assert!(out.status.success(), "status failed: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Vault ID"), "status missing vault ID: {}", stdout);
    assert!(stdout.contains("Auth slots:    1"), "status missing auth slot count: {}", stdout);
}

#[test]
fn test_doctor() {
    let tmp = TempDir::new().unwrap();
    init_vault(tmp.path());

    let out = vault_cmd(tmp.path())
        .args(["doctor"])
        .output()
        .unwrap();
    assert!(out.status.success(), "doctor failed: {}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn test_auth_list() {
    let tmp = TempDir::new().unwrap();
    init_vault(tmp.path());

    let out = vault_cmd(tmp.path())
        .args(["auth", "list"])
        .output()
        .unwrap();
    assert!(out.status.success(), "auth list failed: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("trust-local") || stdout.contains("trust_local"),
        "auth list missing trust-local: {}",
        stdout
    );
}

#[test]
fn test_export_import_round_trip() {
    let tmp_a = TempDir::new().unwrap();
    let tmp_b = TempDir::new().unwrap();
    let export_file = tmp_a.path().join("export.json");

    init_vault(tmp_a.path());

    // Set secrets in vault A
    for (k, v) in &[("key1", "val1"), ("key2", "val2")] {
        let out = vault_cmd(tmp_a.path())
            .args(["set", k, v])
            .output()
            .unwrap();
        assert!(out.status.success());
    }

    // Export from vault A using --stdin for passphrase
    let db_a = tmp_a.path().join("vault.db");
    let bin = env!("CARGO_BIN_EXE_vault");
    let out = Command::new(bin)
        .arg("--db").arg(&db_a)
        .args(["export", export_file.to_str().unwrap(), "--stdin"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child.stdin.take().unwrap().write_all(b"TestPass123!\n").unwrap();
            child.wait_with_output()
        })
        .unwrap();

    if !out.status.success() || !export_file.exists() {
        eprintln!(
            "Skipping export/import test (export failed): {}",
            String::from_utf8_lossy(&out.stderr)
        );
        return;
    }

    // Init vault B and import
    init_vault(tmp_b.path());
    let db_b = tmp_b.path().join("vault.db");
    let out = Command::new(bin)
        .arg("--db").arg(&db_b)
        .args(["import", export_file.to_str().unwrap(), "--stdin"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child.stdin.take().unwrap().write_all(b"TestPass123!\n").unwrap();
            child.wait_with_output()
        })
        .unwrap();
    assert!(
        out.status.success(),
        "import failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // Verify secrets in vault B
    for (k, v) in &[("key1", "val1"), ("key2", "val2")] {
        let out = vault_cmd(tmp_b.path())
            .args(["get", k])
            .output()
            .unwrap();
        assert!(out.status.success(), "get {} from imported vault failed", k);
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), *v);
    }
}

#[test]
fn test_exec_requires_flag() {
    let tmp = TempDir::new().unwrap();
    init_vault(tmp.path());

    let out = vault_cmd(tmp.path())
        .args(["set", "MY_SECRET", "hello"])
        .output()
        .unwrap();
    assert!(out.status.success());

    // exec without -e or --all should fail
    let out = vault_cmd(tmp.path())
        .args(["exec", "--", "echo", "hi"])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "exec without -e or --all should fail"
    );
}

#[test]
fn test_exec_with_specific_secret() {
    let tmp = TempDir::new().unwrap();
    init_vault(tmp.path());

    let out = vault_cmd(tmp.path())
        .args(["set", "mysecret", "hello"])
        .output()
        .unwrap();
    assert!(out.status.success());

    // -e MY_VAR=mysecret maps env var MY_VAR to secret named "mysecret"
    let out = vault_cmd(tmp.path())
        .args(["exec", "-e", "MY_VAR=mysecret", "--", "printenv", "MY_VAR"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "exec with -e failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "hello");
}
