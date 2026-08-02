# vault

Local-first CLI secrets vault with envelope encryption and flexible authentication.

[![Version](https://img.shields.io/badge/version-0.3.0-blue.svg)](Cargo.toml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE-MIT)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg)]()

## Why vault?

- **Flexible authentication** — passphrase (default), kernel keyring, TPM 2.0, macOS Keychain, or Windows DPAPI
- **Envelope encryption** — per-secret keys (RDEKs) wrapped by a vault master key (VKEK)
- **Encrypted at rest** — secret names, values, and keys are all AES-256-GCM encrypted
- **Memory hardened** — zeroize-on-drop, no core dumps for key material

## Installation

### Quick install (Linux / macOS)

```bash
curl -fsSL https://raw.githubusercontent.com/niteshdangi/vault/main/install.sh | sh
```

The installer auto-detects your OS and architecture, downloads the latest release, verifies the SHA-256 checksum, and installs to `~/.local/bin` (or `/usr/local/bin` with sudo). Set `VAULT_INSTALL_DIR` to override.

### Windows (PowerShell)

```powershell
irm https://raw.githubusercontent.com/niteshdangi/vault/main/install.ps1 | iex
```

Downloads the latest release, verifies the SHA-256 checksum, and installs to `%LOCALAPPDATA%\vault\`. The install directory is added to your user PATH automatically. Set `VAULT_INSTALL_DIR` to override.

### Build from source

```bash
# Requires Rust 1.78+ (SQLite is bundled — no system headers needed)
cargo install --path .
```

### Manual download

Grab the binary for your platform from [GitHub Releases](https://github.com/niteshdangi/vault/releases) and place it on your `PATH`.

## Quick Start

```bash
# Initialize a new vault (prompts for passphrase)
vault init

# Or initialize with Linux kernel keyring (no passphrase)
vault init --trust-local

# Store and retrieve secrets
vault set AWS_SECRET_KEY "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
vault get AWS_SECRET_KEY

# List all secrets
vault list

# Use secrets in commands (NAME=secret-name format)
vault exec -e AWS_SECRET_KEY=aws/secret-key -e AWS_ACCESS_KEY=aws/access-key -- aws s3 ls

# Or inject all secrets as env vars
vault exec --all -- env

# Export vault (encrypted backup)
vault export backup.vault

# Import from backup
vault import backup.vault

# Check vault health
vault doctor
```

## Authentication Methods

| Method | Platform | Security Level | Use Case |
|--------|----------|----------------|----------|
| Passphrase | All | High | **Default.** Argon2id-derived key wraps VKEK |
| Trust-local | Linux | Convenience | Machine-bound via kernel keyring. No password. |
| TPM 2.0 | Linux | High | Hardware-bound. VKEK sealed to TPM chip. |
| Keychain | macOS | High | macOS Keychain Services |
| DPAPI | Windows | Medium | Windows user account-bound |

Multiple auth methods can be active simultaneously.

## Architecture

```
┌─────────────┐
│  Passphrase │──┐
│  TPM 2.0    │──┤  Auth Slots
│  Keychain   │──┤  (each wraps VKEK differently)
│  DPAPI      │──┤
│  trust-local│──┘
│             │
│    VKEK     │  Vault Key Encryption Key (256-bit)
│      │      │
│   ┌──┴──┐   │
│  RDEK  RDEK │  Per-secret Record DEKs
│   │     │   │
│  Secret Secret│  AES-256-GCM encrypted
└─────────────┘
```

- **VKEK**: 256-bit master key, never stored in plaintext
- **RDEK**: Unique 256-bit key per secret, wrapped by VKEK
- **Blind indexes**: HMAC-SHA256 for secret lookup without exposing names
- **AAD binding**: All ciphertexts bound to record identity (anti-splicing)

## Commands

| Command | Description |
|---------|-------------|
| `vault init` | Initialize a new vault |
| `vault set <name> [value]` | Store a secret (prompts if value omitted; or `--stdin`) |
| `vault get <name>` | Retrieve a secret value |
| `vault list` | List all secret names |
| `vault delete <name>` | Delete a secret |
| `vault status` | Vault status and metadata |
| `vault doctor` | Security diagnostics |
| `vault lock` | Lock vault — stop agent *(Unix only)* |
| `vault unlock` | Unlock vault — start agent daemon *(Unix only)* |
| `vault exec -- <cmd>` | Run command with secrets as env vars ⚠️ |
| `vault resolve` | Resolve secrets over the OpenClaw SecretRef protocol (stdin/stdout JSON) |
| `vault export [file]` | Export encrypted vault backup (stdout if file omitted) |
| `vault import <file>` | Import from encrypted backup |
| `vault auth list` | List auth slots |
| `vault auth add <type>` | Add auth method |
| `vault auth remove <id>` | Remove auth method |

### Global Flags

| Flag | Description |
|------|-------------|
| `--db <path>` | Path to vault database (default: platform data dir) |

### Command-Specific Flags

| Command | Flag | Description |
|---------|------|-------------|
| `vault init` | `--trust-local` | Use Linux kernel keyring auth *(Linux only)* |
| `vault init` | `--tpm` | Use TPM 2.0 auth *(Linux only)* |
| `vault init` | `--keychain` | Use macOS Keychain auth *(macOS only)* |
| `vault init` | `--dpapi` | Use Windows DPAPI auth *(Windows only)* |
| `vault set` | `--stdin` | Read secret value from stdin |
| `vault unlock` | `--ttl <seconds>` | Agent session TTL (default: 900) |
| `vault exec` | `-e`, `--env NAME=secret` | Map env var NAME to vault secret |
| `vault exec` | `--all` | Inject all secrets as env vars |
| `vault exec` | `--yes` | Skip confirmation prompt for `--all` |
| `vault resolve` | `--protocol <name>` | Output protocol shape (default: `openclaw`) |
| `vault resolve` | `--allow <pattern>` | Restrict resolvable secrets to a glob (repeatable) |
| `vault export` | `--stdin` | Read export passphrase from stdin |
| `vault import` | `--force` | Overwrite existing secrets on collision |
| `vault import` | `--stdin` | Read export passphrase from stdin |
| `vault auth add` | `--force` | Allow trust-local without an existing passphrase slot |

> **⚠️ `vault exec` warning:** Secrets injected as environment variables are visible to any same-UID process via `/proc/<pid>/environ` on Linux. Prefer `vault get` in subshells where possible. Requires explicit `-e NAME=secret` mappings or `--all` flag.

> **Note on `--all`:** Secret names are transformed to env var names by replacing `/`, `-`, `.` with `_` and uppercasing. Collisions are detected and abort execution.

### Agent integration (`vault resolve`)

`vault resolve` implements the [OpenClaw](https://docs.openclaw.ai) `exec` SecretRef
protocol so agents and daemons can fetch secrets non-interactively — no passphrase
prompt, no secrets in config files or environment variables.

It reads a JSON request on stdin and writes JSON to stdout:

```console
$ echo '{"protocolVersion":1,"provider":"vault","ids":["CLOUDFLARE_API_TOKEN"]}' | vault resolve
{"protocolVersion":1,"values":{"CLOUDFLARE_API_TOKEN":"<secret>"}}
```

Missing secrets are reported per-id without failing the whole batch, so one bad
reference does not break an otherwise valid request:

```console
$ echo '{"protocolVersion":1,"ids":["REAL_KEY","NOPE"]}' | vault resolve
{"errors":{"NOPE":{"message":"secret 'NOPE' not found"}},"protocolVersion":1,"values":{"REAL_KEY":"<secret>"}}
```

Unlocking is non-interactive, so this requires an auth method that works unattended
(`--trust-local`, TPM, Keychain, or DPAPI), or a running agent daemon (`vault unlock`).

To wire it into OpenClaw, register vault as an `exec` secret provider:

```json5
{
  secrets: {
    providers: {
      vault: {
        source: "exec",
        command: "vault",
        args: ["resolve", "--allow", "telegram/*"],
      },
    },
  },
}
```

Config values can then reference secrets as
`{ source: "exec", provider: "vault", id: "telegram/botToken" }` instead of
embedding the literal token.

> **Note:** OpenClaw requires the provider `command` to be an absolute path that
> is not group- or world-writable. `chmod 755 ~/.local/bin/vault` if it was
> installed with looser permissions.

#### Scoping access with `--allow`

By default `resolve` can read every secret in the vault. Pass `--allow` to grant
least-privilege access instead — useful when several agents share one vault and
none of them should be able to read all of it.

```console
# This caller can read telegram/botToken but nothing else.
$ vault resolve --allow 'telegram/*'
```

`--allow` is repeatable and the patterns union:

```console
$ vault resolve --allow 'telegram/*' --allow 'github/token'
```

Pattern syntax treats names as `/`-delimited paths:

| Pattern       | Matches                      | Does not match         |
|---------------|------------------------------|------------------------|
| `telegram/*`  | `telegram/botToken`          | `telegram/a/b`         |
| `telegram/**` | `telegram/a`, `telegram/a/b` | `telegram`, `aws/key`  |
| `db?`         | `db1`                        | `db`, `db12`           |
| `**`          | everything                   | —                      |

`*` stays within one segment, `**` crosses segments, and `?` matches a single
non-separator character. There is intentionally no `[a-z]` or `{a,b}` syntax,
because secret names may legitimately contain those characters.

Out-of-scope ids are reported as ordinary `not found` errors, identical to ids
that genuinely do not exist — a restricted caller cannot use `resolve` to probe
for the names of secrets it may not read. A request consisting entirely of
out-of-scope ids is answered without unlocking the vault at all.


## Agent Daemon

The vault agent holds the unlocked VKEK in memory to avoid repeated authentication:

```bash
vault unlock          # Start agent, authenticate once
vault set KEY value   # No re-authentication needed
vault get KEY         # Uses cached VKEK from agent
vault lock            # Stop agent, zeroize keys
```

- **Unix only** — agent is not available on Windows (`#[cfg(unix)]`)
- Unix socket communication (`0600` permissions, parent directory `0700`)
- Socket path: `$XDG_RUNTIME_DIR/vault/agent-<hash>.sock` (or `/tmp/vault-agent-<uid>/` fallback)
- Idle timeout: 15 minutes (configurable via `vault unlock --ttl` or `vault agent --ttl`)
- Absolute max lifetime: 4 hours (hardcoded)
- Memory hardened: `PR_SET_DUMPABLE=0`, zeroize-on-drop
- Peer UID authentication via `SO_PEERCRED` on **Linux only**; on macOS, relies on socket file permissions

> **Advanced:** `vault agent --ttl <seconds>` runs the agent in the foreground. Normally you don't call this directly — `vault unlock` spawns it automatically.

## Security Model

See [SECURITY.md](SECURITY.md) for the full threat model and cryptographic details.

**Crypto primitives:**
- AES-256-GCM (encryption, key wrapping)
- Argon2id (passphrase key derivation, export key derivation)
- HMAC-SHA256 (blind indexes)
- HKDF-SHA256 (subkey derivation)

**What vault protects against:**
- Unauthorized access to secrets at rest
- Database theft (without auth factor)
- Memory scraping (best-effort hardening)
- Record splicing/substitution (AAD binding)

**What vault does NOT protect against:**
- Root/kernel-level compromise
- Same-UID process when agent is unlocked
- Physical access with unlocked session

## Platform Support

| Feature | Linux | macOS | Windows |
|---------|-------|-------|---------|
| Core vault | ✅ | ✅ | ✅ |
| Passphrase auth | ✅ | ✅ | ✅ |
| Trust-local (kernel keyring) | ✅ | — | — |
| TPM 2.0 | ✅ | — | — |
| Keychain | — | ✅ | — |
| DPAPI | — | — | ✅ |
| Agent daemon | ✅ | ✅ | — |

> **Trust-local** is Linux's equivalent of macOS Keychain / Windows DPAPI — OS-level key storage via the kernel keyring, no passphrase required. Works headless (no desktop session needed).

> **Note:** Peer-UID authentication for the agent socket uses `SO_PEERCRED` and is **Linux-only**. On macOS and other Unix platforms, agent security relies on socket file permissions (`0600`) only.

## Building from Source

```bash
# Prerequisites: Rust 1.78+ (SQLite is bundled — no system headers needed)
cargo build --release
```

## Library Usage

vault also ships as a library crate (`vault_lib`) for programmatic access:

```toml
[dependencies]
vault_lib = { path = "." }
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Licensed under [MIT License](LICENSE-MIT).
