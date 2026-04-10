//! AES-256-GCM encryption and decryption.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AesError {
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("decryption failed")]
    DecryptionFailed,

}

/// Encrypt with associated data (AAD).
pub fn encrypt_with_aad(
    key: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, [u8; 12]), AesError> {
    use aes_gcm::aead::Payload;

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| AesError::EncryptionFailed)?;

    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let payload = Payload {
        msg: plaintext,
        aad,
    };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|_| AesError::EncryptionFailed)?;

    Ok((ciphertext, nonce_bytes))
}

/// Decrypt with associated data (AAD).
pub fn decrypt_with_aad(
    key: &[u8; 32],
    ciphertext: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
) -> Result<Vec<u8>, AesError> {
    use aes_gcm::aead::Payload;

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| AesError::DecryptionFailed)?;
    let nonce = Nonce::from_slice(nonce);

    let payload = Payload {
        msg: ciphertext,
        aad,
    };

    cipher
        .decrypt(nonce, payload)
        .map_err(|_| AesError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    fn random_key() -> [u8; 32] {
        let mut k = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut k);
        k
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let key = random_key();
        let plaintext = b"hello, vault!";
        let aad = b"test-aad";
        let (ct, nonce) = encrypt_with_aad(&key, plaintext, aad).unwrap();
        let pt = decrypt_with_aad(&key, &ct, &nonce, aad).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn encrypt_with_empty_plaintext() {
        let key = random_key();
        let (ct, nonce) = encrypt_with_aad(&key, b"", b"aad").unwrap();
        let pt = decrypt_with_aad(&key, &ct, &nonce, b"aad").unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn encrypt_with_large_data() {
        let key = random_key();
        let big = vec![0xABu8; 1_000_000];
        let (ct, nonce) = encrypt_with_aad(&key, &big, b"").unwrap();
        let pt = decrypt_with_aad(&key, &ct, &nonce, b"").unwrap();
        assert_eq!(pt, big);
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let key1 = random_key();
        let key2 = random_key();
        let (ct, nonce) = encrypt_with_aad(&key1, b"secret", b"aad").unwrap();
        assert!(decrypt_with_aad(&key2, &ct, &nonce, b"aad").is_err());
    }

    #[test]
    fn decrypt_tampered_ciphertext_fails() {
        let key = random_key();
        let (mut ct, nonce) = encrypt_with_aad(&key, b"secret", b"aad").unwrap();
        ct[0] ^= 0xFF;
        assert!(decrypt_with_aad(&key, &ct, &nonce, b"aad").is_err());
    }

    #[test]
    fn decrypt_wrong_aad_fails() {
        let key = random_key();
        let (ct, nonce) = encrypt_with_aad(&key, b"secret", b"correct-aad").unwrap();
        assert!(decrypt_with_aad(&key, &ct, &nonce, b"wrong-aad").is_err());
    }

    #[test]
    fn decrypt_wrong_nonce_fails() {
        let key = random_key();
        let (ct, _nonce) = encrypt_with_aad(&key, b"secret", b"aad").unwrap();
        let wrong_nonce = [0u8; 12];
        assert!(decrypt_with_aad(&key, &ct, &wrong_nonce, b"aad").is_err());
    }

    #[test]
    fn different_encryptions_produce_different_nonces() {
        let key = random_key();
        let (_, n1) = encrypt_with_aad(&key, b"data", b"").unwrap();
        let (_, n2) = encrypt_with_aad(&key, b"data", b"").unwrap();
        assert_ne!(n1, n2);
    }
}
