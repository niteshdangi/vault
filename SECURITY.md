# Security Policy

## Threat Model

### What vault protects against

- **Unauthorized access to secrets at rest** — all secret names and values are encrypted with AES-256-GCM using per-record keys (RDEKs). The RDEKs themselves are wrapped by the Vault Key Encryption Key (VKEK).
- **Plaintext secret name exposure** — secret names are encrypted; lookups use HMAC-SHA256 blind indexes derived from the VKEK.
- **Offline brute-force of passphrase-protected vaults** — passphrase-derived keys use Argon2id with tunable memory/time parameters.
- **Accidental secret leakage** — secrets are never printed to logs. `PR_SET_DUMPABLE=0` is set in agent mode to prevent core dumps.

### What vault does NOT protect against

- **Same-UID compromise** — any process running as the same user can access the Unix socket agent, read the database file, and interact with OS keystores. Vault is not a privilege isolation boundary.
- **Root/kernel-level compromise** — a root attacker can read process memory, keyring entries, and database files.
- **Physical access with disk forensics** — while secrets are encrypted, SQLite WAL/free pages may retain historical ciphertext. See [SQLite Deletion Semantics](#sqlite-deletion-semantics).
- **Side-channel attacks** — vault does not claim constant-time guarantees across all operations.

## Trust Boundaries

| Boundary | Trust Level | Notes |
|----------|-------------|-------|
| Same user (UID) | **Trusted** | Agent socket, DB files, and OS keystores are accessible to all same-UID processes |
| Same machine, different user | **Untrusted** | DB permissions `0600`, socket `0600`, parent directories `0700` |
| Network | **Untrusted** | Vault has no network surface. All operations are local. |

## Authentication Levels

| Level | Platform | Description |
|-------|----------|-------------|
| **Passphrase** | All | VKEK wrapped with Argon2id-derived key. Default and strongest portable option. |
| **trust-local** | Linux | VKEK stored in Linux session keyring, wrapped with machine-derived key. Convenience mode — see [caveats](#trust-local-caveats). |
| **TPM** | Linux | VKEK sealed to TPM 2.0 via `tpm2-tools`. Hardware-bound authentication. |
| **Keychain** | macOS | VKEK stored in macOS Keychain Services. |
| **DPAPI** | Windows | VKEK protected by Windows Data Protection API. |

## Trust-Local Caveats

`trust-local` is a **convenience mode**, not a security boundary. It:

- Derives its wrapping key from the machine identity (`/etc/machine-id`)
- Stores the VKEK in the Linux kernel session keyring
- Is accessible to any process running as the same UID
- Should **not** be the sole authentication method on shared or untrusted machines
- Is intended for single-user development machines where passphrase entry is impractical

**Recommendation:** Always maintain at least one passphrase slot alongside trust-local.

## Agent Security Model

The vault agent is a local daemon that caches the unlocked VKEK in memory:

- Listens on a Unix domain socket (`$XDG_RUNTIME_DIR/vault/agent.sock`)
- Authenticates clients by peer UID on Linux (`SO_PEERCRED`); on other Unix platforms, relies on socket file permissions only
- Socket permissions: `0600`
- Sets `PR_SET_DUMPABLE=0` (Linux) to prevent ptrace/core dump access
- Key material is zeroized on drop; `mlock` is **not** currently used (planned)
- Auto-locks after a configurable TTL (default: 15 minutes)
- Key material is zeroized on lock/shutdown

**Important:** The agent provides convenience caching, not privilege isolation. Any same-UID process can request the VKEK while the agent is unlocked.

## SQLite Deletion Semantics

Vault uses SQLite with WAL (Write-Ahead Logging) mode:

- `PRAGMA secure_delete=ON` is enabled to overwrite deleted content
- However, WAL files (`vault.db-wal`) may retain historical page data
- SQLite free pages may contain remnants of old rows
- `DELETE` removes the logical record but physical cleanup depends on SQLite's page management

**Implications:**
- Deleting a secret removes it from normal access but ciphertext fragments may persist on disk
- For high-assurance deletion, consider periodic `VACUUM` and secure filesystem-level erasure
- All persisted data is encrypted, so remnants require the VKEK to decrypt

## Export Format Security

Exported vault files use:

- **Key derivation:** Argon2id with a separate export passphrase (not the vault passphrase)
- **Encryption:** AES-256-GCM for the serialized secret payload
- **Format:** JSON envelope with metadata + encrypted blob

Export files are self-contained and portable. The export passphrase should be strong and transmitted separately from the export file.

## Cryptographic Primitives

| Primitive | Usage | Implementation |
|-----------|-------|----------------|
| **AES-256-GCM** | Secret encryption, key wrapping, export encryption | `aes-gcm` crate (RustCrypto) |
| **Argon2id** | Passphrase key derivation, export key derivation | `argon2` crate (RustCrypto) |
| **HMAC-SHA256** | Blind index generation for secret lookup | `hmac` + `sha2` crates (RustCrypto) |
| **HKDF-SHA256** | Subkey derivation from VKEK | `hkdf` crate (RustCrypto) |
| **OS RNG** | Nonce generation, key generation | `rand::rngs::OsRng` |

All cryptographic implementations come from the [RustCrypto](https://github.com/RustCrypto) project. No custom cryptographic algorithms are used.

### Why these choices

- **AES-256-GCM**: Industry-standard AEAD cipher with hardware acceleration on modern CPUs. Provides both confidentiality and integrity.
- **Argon2id**: Winner of the Password Hashing Competition. Memory-hard to resist GPU/ASIC attacks. The `id` variant combines resistance to both side-channel and GPU attacks.
- **HMAC-SHA256**: Deterministic, keyed hash for blind indexes. Allows O(1) secret lookup without exposing plaintext names.
- **HKDF**: Standard key derivation for deriving domain-separated subkeys from the VKEK.

## Reporting Vulnerabilities

**Do not open public issues for security vulnerabilities.**

To report a vulnerability:

1. **GitHub Security Advisories** (preferred): Use [GitHub's private vulnerability reporting](https://github.com/niteshdangi/vault/security/advisories/new)
2. **Email**: Contact the maintainer directly at the email listed in the GitHub profile

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if any)

We aim to acknowledge reports within 48 hours and provide a fix or mitigation plan within 7 days for critical issues.

## Disclosure Policy

- We follow coordinated disclosure
- Security fixes are released as patch versions
- CVEs are requested for significant vulnerabilities
- Credit is given to reporters (unless anonymity is requested)
