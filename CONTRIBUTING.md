# Contributing to vault

Thank you for your interest in contributing to vault. This is a security-sensitive project — please read these guidelines carefully.

## Development Setup

### Prerequisites

- Rust toolchain (stable, >= 1.78) — install via [rustup](https://rustup.rs/)
- Linux recommended for full feature testing (trust-local, keyring, agent)

### Building

```bash
git clone https://github.com/niteshdangi/vault.git
cd vault
cargo build
```

### Running

```bash
cargo run -- init
cargo run -- set test/key "hello"
cargo run -- get test/key
```

## Code Style

All code must pass:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
```

Configure your editor to run `cargo fmt` on save. We use default rustfmt settings.

## Testing

```bash
cargo test --all-targets
```

- Write tests for new functionality
- Crypto operations must have round-trip tests
- Auth backends should be tested with temporary databases
- Integration tests go in `tests/`

## Pull Request Process

1. **Fork** the repository and create a feature branch from `main`
2. **Keep PRs focused** — one logical change per PR
3. **Write clear commit messages** using [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat: add keychain auth backend`
   - `fix: zeroize derived key in passphrase slot creation`
   - `docs: update auth method table in README`
   - `refactor: split vault.rs into focused modules`
   - `test: add export/import round-trip tests`
   - `ci: add macOS build matrix`
4. **Ensure CI passes** — all checks must be green before merge
5. **Update documentation** if your change affects CLI behavior, security model, or public API

## Security-Sensitive Changes

Changes that touch the following areas require **extra review** and explicit sign-off:

- `src/crypto/` — any cryptographic operation
- `src/auth/` — authentication backends and slot management
- `src/agent/` — agent daemon, IPC, key caching
- `src/store/` — database operations, schema changes
- Key derivation parameters
- Memory handling (zeroization, mlock)
- Export/import format

For security changes:

- Explain the threat model impact in the PR description
- Reference any relevant CVEs or advisories
- Add tests that verify the security property
- Consider backward compatibility for stored data

## How to Add a New Auth Backend

Auth backends live in `src/auth/`. To add a new one:

1. **Create the module** — `src/auth/yourbackend.rs`
2. **Implement key operations:**
   - `seal(vkek: &[u8]) -> Result<Vec<u8>>` — wrap/protect the VKEK using your backend
   - `unseal(wrapped: &[u8]) -> Result<[u8; 32]>` — unwrap/recover the VKEK
   - `remove()` — clean up any backend-specific state
3. **Register the slot type** in `src/auth/slot.rs`
4. **Add CLI flags** in `src/main.rs` for `init` and `auth add`
5. **Gate with `#[cfg(target_os = "...")]`** if platform-specific
6. **Add platform-specific dependencies** under `[target.'cfg(...)'.dependencies]` in `Cargo.toml`
7. **Document** the backend in README.md and SECURITY.md
8. **Write tests** — at minimum a seal/unseal round-trip

### Backend checklist

- [ ] Key material is zeroized after use
- [ ] No plaintext keys written to predictable file paths
- [ ] Error paths clean up partial state
- [ ] Platform availability is checked at runtime with clear error messages
- [ ] Security properties and caveats are documented

## Reporting Security Issues

See [SECURITY.md](SECURITY.md) for vulnerability reporting instructions. **Do not open public issues for security vulnerabilities.**

## License

By contributing, you agree that your contributions will be licensed under the same terms as the project: MIT OR Apache-2.0.
