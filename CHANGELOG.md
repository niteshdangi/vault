# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-04-10

### Added
- AES-256-GCM envelope encryption with per-secret RDEKs
- HMAC-SHA256 blind indexes for secret names
- Multiple auth backends: passphrase (Argon2id), trust-local (Linux keyring), TPM 2.0, macOS Keychain, Windows DPAPI
- Agent daemon for session caching with automatic VKEK zeroization
- Encrypted export/import with passphrase-protected envelopes
- `vault exec` for injecting secrets as environment variables
- `vault doctor` diagnostics
- Auth slot management (add/remove/list)
- Library crate (`vault_lib`) for programmatic access
- 63 tests: crypto, store, vault operations, CLI integration
- Cross-platform cfg gating (Linux, macOS, Windows)
- MIT/Apache-2.0 dual license

### Security
- Per-vault keyring scoping for trust-local
- Transactional init and import operations
- `exec` requires explicit `-e` or `--all` flag
- Agent cooperative shutdown with VKEK zeroization
- Auth-slot backend cleanup on removal
- Env var name validation in exec
