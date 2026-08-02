# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-08-02

### Added
- `vault resolve --allow <pattern>` restricts which secrets a caller may
  resolve, giving unattended consumers least-privilege access instead of
  all-or-nothing access to the vault. Repeatable; patterns union. Supports
  `*` (within one `/` segment), `**` (across segments), and `?` (single
  non-separator character).
- Integration test coverage for `vault resolve`, which previously had none.

### Security
- Out-of-scope ids in `resolve` are reported as `not found`, identical to
  genuinely missing ids, so a scoped caller cannot enumerate secret names it
  is not permitted to read.
- A `resolve` request containing only out-of-scope ids is answered without
  unwrapping the VKEK.

## [0.2.0] - 2026-08-02

### Added
- `vault resolve` subcommand implementing the OpenClaw `exec` SecretRef protocol
  (protocolVersion 1). Reads a JSON request on stdin (`{protocolVersion, provider, ids}`)
  and writes `{protocolVersion, values, errors?}` on stdout, resolving each id
  non-interactively so unattended agents can fetch secrets without a passphrase prompt.
  Per-id failures are reported in `errors` without failing the whole batch.
- `--protocol` flag on `resolve` (currently only `openclaw`), reserving the namespace
  for future protocol shapes.

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
