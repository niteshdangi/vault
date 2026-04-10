//! Argon2id key derivation.

use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use thiserror::Error;

/// Argon2id parameters matching design spec.
pub const TIME_COST: u32 = 3;
pub const MEMORY_COST: u32 = 65536; // 64 MiB
pub const PARALLELISM: u32 = 4;
pub const OUTPUT_LEN: usize = 32;
pub const SALT_LEN: usize = 32;

#[derive(Debug, Error)]
pub enum Argon2Error {
    #[error("key derivation failed: {0}")]
    DerivationFailed(String),
}

/// Derive a 32-byte key from a passphrase using default Argon2id params.
/// Returns (derived_key, salt).
pub fn derive_key(passphrase: &[u8]) -> Result<([u8; 32], [u8; SALT_LEN]), Argon2Error> {
    let mut salt = [0u8; SALT_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let key = derive_key_with_salt(passphrase, &salt)?;
    Ok((key, salt))
}

/// Derive a 32-byte key from a passphrase and existing salt using default params.
pub fn derive_key_with_salt(passphrase: &[u8], salt: &[u8]) -> Result<[u8; 32], Argon2Error> {
    derive_key_with_params(passphrase, salt, TIME_COST, MEMORY_COST, PARALLELISM)
}

/// Derive a 32-byte key from a passphrase and existing salt using explicit params.
pub fn derive_key_with_params(
    passphrase: &[u8],
    salt: &[u8],
    time_cost: u32,
    memory_cost: u32,
    parallelism: u32,
) -> Result<[u8; 32], Argon2Error> {
    let params = Params::new(memory_cost, time_cost, parallelism, Some(OUTPUT_LEN))
        .map_err(|e| Argon2Error::DerivationFailed(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = [0u8; OUTPUT_LEN];
    argon2
        .hash_password_into(passphrase, salt, &mut output)
        .map_err(|e| Argon2Error::DerivationFailed(e.to_string()))?;

    Ok(output)
}

/// Get the Argon2id parameters as a JSON-serializable string.
pub fn params_json() -> String {
    serde_json::json!({
        "algorithm": "argon2id",
        "version": "0x13",
        "time_cost": TIME_COST,
        "memory_cost": MEMORY_COST,
        "parallelism": PARALLELISM,
        "output_len": OUTPUT_LEN,
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_key_deterministic() {
        let pass = b"password";
        let salt = [42u8; SALT_LEN];
        let k1 = derive_key_with_salt(pass, &salt).unwrap();
        let k2 = derive_key_with_salt(pass, &salt).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn derive_key_different_salts() {
        let pass = b"password";
        let salt_a = [1u8; SALT_LEN];
        let salt_b = [2u8; SALT_LEN];
        let k1 = derive_key_with_salt(pass, &salt_a).unwrap();
        let k2 = derive_key_with_salt(pass, &salt_b).unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn derive_key_different_passwords() {
        let salt = [99u8; SALT_LEN];
        let k1 = derive_key_with_salt(b"alpha", &salt).unwrap();
        let k2 = derive_key_with_salt(b"bravo", &salt).unwrap();
        assert_ne!(k1, k2);
    }
}
