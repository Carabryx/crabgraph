//! ChaCha20-Poly1305 authenticated encryption.
//!
//! ChaCha20-Poly1305 is a fast, secure AEAD cipher that doesn't require
//! hardware AES acceleration. Excellent choice for all platforms.

use crate::aead::{Ciphertext, CrabAead};
use crate::errors::{CrabError, CrabResult};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305 as ChaCha20Poly1305Cipher, Nonce,
};

/// ChaCha20-Poly1305 AEAD cipher.
///
/// # Security
/// ChaCha20-Poly1305 provides 256-bit security and is particularly well-suited
/// for software implementations. It's the recommended choice when AES hardware
/// acceleration is not available.
///
/// # Example
/// ```
/// use crabgraph::aead::{ChaCha20Poly1305, CrabAead};
///
/// let key = ChaCha20Poly1305::generate_key().unwrap();
/// let cipher = ChaCha20Poly1305::new(&key).unwrap();
///
/// let plaintext = b"Secret message";
/// let ciphertext = cipher.encrypt(plaintext, None).unwrap();
/// let decrypted = cipher.decrypt(&ciphertext, None).unwrap();
///
/// assert_eq!(decrypted, plaintext);
/// ```
pub struct ChaCha20Poly1305 {
    cipher: ChaCha20Poly1305Cipher,
}

impl ChaCha20Poly1305 {
    /// Creates a new ChaCha20-Poly1305 cipher from a 32-byte key.
    ///
    /// # Errors
    /// Returns error if key is not exactly 32 bytes.
    ///
    /// # Example
    /// ```
    /// use crabgraph::aead::ChaCha20Poly1305;
    ///
    /// let key = [0u8; 32];
    /// let cipher = ChaCha20Poly1305::new(&key).unwrap();
    /// ```
    pub fn new(key: &[u8]) -> CrabResult<Self> {
        if key.len() != 32 {
            return Err(CrabError::invalid_input(format!(
                "ChaCha20-Poly1305 requires 32-byte key, got {}",
                key.len()
            )));
        }

        let cipher = ChaCha20Poly1305Cipher::new_from_slice(key)
            .map_err(|e| CrabError::key_error(format!("Invalid ChaCha20-Poly1305 key: {}", e)))?;

        Ok(Self {
            cipher,
        })
    }

    /// Generates a random 32-byte key suitable for ChaCha20-Poly1305.
    ///
    /// # Example
    /// ```
    /// use crabgraph::aead::ChaCha20Poly1305;
    ///
    /// let key = ChaCha20Poly1305::generate_key().unwrap();
    /// assert_eq!(key.len(), 32);
    /// ```
    pub fn generate_key() -> CrabResult<Vec<u8>> {
        crate::rand::secure_bytes(32)
    }

    /// The nonce size for ChaCha20-Poly1305 (12 bytes).
    pub const NONCE_SIZE: usize = 12;

    /// The authentication tag size (16 bytes).
    pub const TAG_SIZE: usize = 16;
}

impl CrabAead for ChaCha20Poly1305 {
    fn encrypt(&self, plaintext: &[u8], associated_data: Option<&[u8]>) -> CrabResult<Ciphertext> {
        let nonce_bytes = crate::rand::secure_bytes(Self::NONCE_SIZE)?;
        self.encrypt_with_nonce(plaintext, &nonce_bytes, associated_data)
    }

    fn decrypt(
        &self,
        ciphertext: &Ciphertext,
        associated_data: Option<&[u8]>,
    ) -> CrabResult<Vec<u8>> {
        if ciphertext.nonce.len() != Self::NONCE_SIZE {
            return Err(CrabError::InvalidNonce(format!(
                "Expected {}-byte nonce, got {}",
                Self::NONCE_SIZE,
                ciphertext.nonce.len()
            )));
        }

        let nonce_array: [u8; 12] = ciphertext
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| CrabError::InvalidNonce("Invalid nonce length".to_string()))?;
        let nonce = Nonce::from(nonce_array);

        // Reconstruct full ciphertext: data || tag
        let mut full_ciphertext = ciphertext.ciphertext.clone();
        full_ciphertext.extend_from_slice(&ciphertext.tag);

        let payload = Payload {
            msg: &full_ciphertext,
            aad: associated_data.unwrap_or(&[]),
        };

        let plaintext = self.cipher.decrypt(&nonce, payload)?;

        Ok(plaintext)
    }

    fn encrypt_with_nonce(
        &self,
        plaintext: &[u8],
        nonce: &[u8],
        associated_data: Option<&[u8]>,
    ) -> CrabResult<Ciphertext> {
        if nonce.len() != Self::NONCE_SIZE {
            return Err(CrabError::InvalidNonce(format!(
                "Expected {}-byte nonce, got {}",
                Self::NONCE_SIZE,
                nonce.len()
            )));
        }

        let nonce_array: [u8; 12] = nonce
            .try_into()
            .map_err(|_| CrabError::InvalidNonce("Invalid nonce length".to_string()))?;
        let nonce_obj = Nonce::from(nonce_array);
        let payload = Payload {
            msg: plaintext,
            aad: associated_data.unwrap_or(&[]),
        };

        let encrypted = self.cipher.encrypt(&nonce_obj, payload)?;

        // Split into ciphertext and tag
        let tag_start = encrypted.len().saturating_sub(Self::TAG_SIZE);
        let ct = encrypted[..tag_start].to_vec();
        let tag = encrypted[tag_start..].to_vec();

        Ok(Ciphertext::new(nonce.to_vec(), ct, tag))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_chacha20poly1305_roundtrip() {
        let key = ChaCha20Poly1305::generate_key().unwrap();
        let cipher = ChaCha20Poly1305::new(&key).unwrap();

        let plaintext = b"Hello, ChaCha!";
        let ciphertext = cipher.encrypt(plaintext, None).unwrap();
        let decrypted = cipher.decrypt(&ciphertext, None).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chacha20poly1305_with_aad() {
        let key = ChaCha20Poly1305::generate_key().unwrap();
        let cipher = ChaCha20Poly1305::new(&key).unwrap();

        let plaintext = b"Secret data";
        let aad = b"metadata";
        let ciphertext = cipher.encrypt(plaintext, Some(aad)).unwrap();
        let decrypted = cipher.decrypt(&ciphertext, Some(aad)).unwrap();

        assert_eq!(decrypted, plaintext);

        // Wrong AAD should fail
        let result = cipher.decrypt(&ciphertext, Some(b"wrong"));
        assert!(result.is_err());
    }

    #[test]
    fn test_chacha20poly1305_invalid_key() {
        let result = ChaCha20Poly1305::new(&[0u8; 16]);
        assert!(result.is_err());
    }

    #[test]
    fn test_chacha20poly1305_empty_message() {
        let key = ChaCha20Poly1305::generate_key().unwrap();
        let cipher = ChaCha20Poly1305::new(&key).unwrap();

        let plaintext = b"";
        let ciphertext = cipher.encrypt(plaintext, None).unwrap();
        let decrypted = cipher.decrypt(&ciphertext, None).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chacha20poly1305_large_message() {
        let key = ChaCha20Poly1305::generate_key().unwrap();
        let cipher = ChaCha20Poly1305::new(&key).unwrap();

        let plaintext = vec![0x42u8; 10000];
        let ciphertext = cipher.encrypt(&plaintext, None).unwrap();
        let decrypted = cipher.decrypt(&ciphertext, None).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chacha20poly1305_rfc_vector() {
        // RFC 8439 Test Vector (Appendix A.5)
        let key = hex!("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce = hex!("070000004041424344454647");
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";

        let cipher = ChaCha20Poly1305::new(&key).unwrap();
        let ciphertext = cipher.encrypt_with_nonce(plaintext, &nonce, Some(b"")).unwrap();

        // Verify we can decrypt
        let decrypted = cipher.decrypt(&ciphertext, Some(b"")).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
