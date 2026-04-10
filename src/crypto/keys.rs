//! Key generation, wrapping, and unwrapping for VKEK and RDEK.

use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::aes;

/// Vault Key Encryption Key — the root key for the vault.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Vkek {
    key: [u8; 32],
}

impl Vkek {
    /// Generate a new random VKEK.
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        Self { key }
    }

    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { key: bytes }
    }

    /// Get the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }

    /// Wrap (encrypt) this VKEK with a wrapping key, with AAD = b"vkek-wrap".
    pub fn wrap(&self, wrapping_key: &[u8; 32]) -> anyhow::Result<(Vec<u8>, [u8; 12])> {
        aes::encrypt_with_aad(wrapping_key, &self.key, b"vkek-wrap").map_err(|e| anyhow::anyhow!(e))
    }

    /// Unwrap (decrypt) a VKEK from ciphertext using a wrapping key, with AAD = b"vkek-wrap".
    pub fn unwrap(
        wrapping_key: &[u8; 32],
        wrapped: &[u8],
        nonce: &[u8; 12],
    ) -> anyhow::Result<Self> {
        let mut plaintext = aes::decrypt_with_aad(wrapping_key, wrapped, nonce, b"vkek-wrap")
            .map_err(|e| anyhow::anyhow!(e))?;

        if plaintext.len() != 32 {
            plaintext.zeroize();
            anyhow::bail!("invalid VKEK length after unwrap");
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&plaintext);
        plaintext.zeroize();

        Ok(Self { key })
    }
}

/// Record Data Encryption Key — per-secret key.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Rdek {
    key: [u8; 32],
}

impl Rdek {
    /// Generate a new random RDEK.
    pub fn generate() -> Self {
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        Self { key }
    }

    /// Create from raw bytes.
    #[allow(dead_code)]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { key: bytes }
    }

    /// Get the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }

    /// Wrap this RDEK with the VKEK, using AAD for context binding.
    pub fn wrap_with_aad(&self, vkek: &Vkek, aad: &[u8]) -> anyhow::Result<(Vec<u8>, [u8; 12])> {
        aes::encrypt_with_aad(vkek.as_bytes(), &self.key, aad).map_err(|e| anyhow::anyhow!(e))
    }

    /// Unwrap an RDEK from ciphertext using the VKEK, with AAD for context binding.
    pub fn unwrap_with_aad(
        vkek: &Vkek,
        wrapped: &[u8],
        nonce: &[u8; 12],
        aad: &[u8],
    ) -> anyhow::Result<Self> {
        let mut plaintext = aes::decrypt_with_aad(vkek.as_bytes(), wrapped, nonce, aad)
            .map_err(|e| anyhow::anyhow!(e))?;

        if plaintext.len() != 32 {
            plaintext.zeroize();
            anyhow::bail!("invalid RDEK length after unwrap");
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&plaintext);
        plaintext.zeroize();

        Ok(Self { key })
    }
}

/// HKDF-SHA256 extract-and-expand using the `hkdf` crate.
pub fn hkdf_sha256(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hk = Hkdf::<Sha256>::new(Some(b"vault-hkdf-salt"), ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vkek_generation_is_random() {
        let a = Vkek::generate();
        let b = Vkek::generate();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn rdek_generation_is_random() {
        let a = Rdek::generate();
        let b = Rdek::generate();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn rdek_wrap_unwrap_round_trip() {
        let vkek = Vkek::generate();
        let rdek = Rdek::generate();
        let aad = b"test-record";
        let (wrapped, nonce) = rdek.wrap_with_aad(&vkek, aad).unwrap();
        let unwrapped = Rdek::unwrap_with_aad(&vkek, &wrapped, &nonce, aad).unwrap();
        assert_eq!(rdek.as_bytes(), unwrapped.as_bytes());
    }

    #[test]
    fn rdek_unwrap_wrong_vkek_fails() {
        let vkek1 = Vkek::generate();
        let vkek2 = Vkek::generate();
        let rdek = Rdek::generate();
        let aad = b"rec";
        let (wrapped, nonce) = rdek.wrap_with_aad(&vkek1, aad).unwrap();
        assert!(Rdek::unwrap_with_aad(&vkek2, &wrapped, &nonce, aad).is_err());
    }

    #[test]
    fn rdek_unwrap_tampered_blob_fails() {
        let vkek = Vkek::generate();
        let rdek = Rdek::generate();
        let aad = b"rec";
        let (mut wrapped, nonce) = rdek.wrap_with_aad(&vkek, aad).unwrap();
        wrapped[0] ^= 0xFF;
        assert!(Rdek::unwrap_with_aad(&vkek, &wrapped, &nonce, aad).is_err());
    }

    #[test]
    fn vkek_wrap_unwrap_round_trip() {
        let vkek = Vkek::generate();
        let mut wrapping_key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut wrapping_key);
        let (wrapped, nonce) = vkek.wrap(&wrapping_key).unwrap();
        let unwrapped = Vkek::unwrap(&wrapping_key, &wrapped, &nonce).unwrap();
        assert_eq!(vkek.as_bytes(), unwrapped.as_bytes());
    }
}
