//! Library crate for the vault secrets manager.
//!
//! Provides envelope encryption, key management, and secret storage
//! for the CLI binary and any downstream consumers.

pub mod crypto;
pub mod store;
pub mod auth;
pub mod vault;
#[cfg(unix)]
pub mod agent;
pub mod error;
