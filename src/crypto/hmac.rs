//! HMAC-SHA256 blind index generation.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::keys::{hkdf_sha256, Vkek};

/// Compute a blind index for a secret name using HMAC-SHA256.
/// The HMAC key is derived from the VKEK using HKDF.
pub fn blind_index(vkek: &Vkek, name: &str) -> Vec<u8> {
    let hmac_key = hkdf_sha256(vkek.as_bytes(), b"blind-index");

    let mut mac = Hmac::<Sha256>::new_from_slice(&hmac_key).expect("HMAC accepts any key length");
    mac.update(name.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::Vkek;

    #[test]
    fn blind_index_deterministic() {
        let vkek = Vkek::from_bytes([7u8; 32]);
        let a = blind_index(&vkek, "my-secret");
        let b = blind_index(&vkek, "my-secret");
        assert_eq!(a, b);
    }

    #[test]
    fn blind_index_different_names() {
        let vkek = Vkek::from_bytes([7u8; 32]);
        let a = blind_index(&vkek, "alpha");
        let b = blind_index(&vkek, "bravo");
        assert_ne!(a, b);
    }

    #[test]
    fn blind_index_different_keys() {
        let vkek_a = Vkek::from_bytes([1u8; 32]);
        let vkek_b = Vkek::from_bytes([2u8; 32]);
        let a = blind_index(&vkek_a, "same-name");
        let b = blind_index(&vkek_b, "same-name");
        assert_ne!(a, b);
    }
}
