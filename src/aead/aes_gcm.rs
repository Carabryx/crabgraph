//! AES-GCM authenticated encryption.
//!
//! Provides AES-128-GCM and AES-256-GCM implementations.

use crate::aead::{Ciphertext, CrabAead};
use crate::errors::{CrabError, CrabResult};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes128Gcm, Aes256Gcm, Nonce,
};

/// AES-128-GCM cipher (128-bit key).
///
/// # Security
/// AES-128-GCM provides 128-bit security with authenticated encryption.
/// Suitable for most applications. Use AES-256-GCM if you need 256-bit security.
pub struct AesGcm128 {
    cipher: Aes128Gcm,
}

impl AesGcm128 {
    /// Creates a new AES-128-GCM cipher from a 16-byte key.
    ///
    /// # Errors
    /// Returns error if key is not exactly 16 bytes.
    ///
    /// # Example
    /// ```
    /// use crabgraph::aead::AesGcm128;
    ///
    /// let key = [0u8; 16];
    /// let cipher = AesGcm128::new(&key).unwrap();
    /// ```
    pub fn new(key: &[u8]) -> CrabResult<Self> {
        if key.len() != 16 {
            return Err(CrabError::invalid_input(format!(
                "AES-128 requires 16-byte key, got {}",
                key.len()
            )));
        }

        let cipher = Aes128Gcm::new_from_slice(key)
            .map_err(|e| CrabError::key_error(format!("Invalid AES-128 key: {}", e)))?;

        Ok(Self {
            cipher,
        })
    }

    /// Generates a random 16-byte key suitable for AES-128-GCM.
    ///
    /// # Example
    /// ```
    /// use crabgraph::aead::AesGcm128;
    ///
    /// let key = AesGcm128::generate_key().unwrap();
    /// assert_eq!(key.len(), 16);
    /// ```
    pub fn generate_key() -> CrabResult<Vec<u8>> {
        crate::rand::secure_bytes(16)
    }

    /// The nonce size for AES-GCM (12 bytes).
    pub const NONCE_SIZE: usize = 12;

    /// The authentication tag size (16 bytes).
    pub const TAG_SIZE: usize = 16;
}

impl CrabAead for AesGcm128 {
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

/// AES-256-GCM cipher (256-bit key).
///
/// # Security
/// AES-256-GCM provides 256-bit security with authenticated encryption.
/// Recommended for high-security applications.
pub struct AesGcm256 {
    cipher: Aes256Gcm,
}

impl AesGcm256 {
    /// Creates a new AES-256-GCM cipher from a 32-byte key.
    ///
    /// # Errors
    /// Returns error if key is not exactly 32 bytes.
    ///
    /// # Example
    /// ```
    /// use crabgraph::aead::AesGcm256;
    ///
    /// let key = [0u8; 32];
    /// let cipher = AesGcm256::new(&key).unwrap();
    /// ```
    pub fn new(key: &[u8]) -> CrabResult<Self> {
        if key.len() != 32 {
            return Err(CrabError::invalid_input(format!(
                "AES-256 requires 32-byte key, got {}",
                key.len()
            )));
        }

        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| CrabError::key_error(format!("Invalid AES-256 key: {}", e)))?;

        Ok(Self {
            cipher,
        })
    }

    /// Generates a random 32-byte key suitable for AES-256-GCM.
    ///
    /// # Example
    /// ```
    /// use crabgraph::aead::AesGcm256;
    ///
    /// let key = AesGcm256::generate_key().unwrap();
    /// assert_eq!(key.len(), 32);
    /// ```
    pub fn generate_key() -> CrabResult<Vec<u8>> {
        crate::rand::secure_bytes(32)
    }

    /// The nonce size for AES-GCM (12 bytes).
    pub const NONCE_SIZE: usize = 12;

    /// The authentication tag size (16 bytes).
    pub const TAG_SIZE: usize = 16;
}

impl CrabAead for AesGcm256 {
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

    #[test]
    fn test_aes128_roundtrip() {
        let key = AesGcm128::generate_key().unwrap();
        let cipher = AesGcm128::new(&key).unwrap();

        let plaintext = b"Hello, World!";
        let ciphertext = cipher.encrypt(plaintext, None).unwrap();
        let decrypted = cipher.decrypt(&ciphertext, None).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes256_roundtrip() {
        let key = AesGcm256::generate_key().unwrap();
        let cipher = AesGcm256::new(&key).unwrap();

        let plaintext = b"Secret message";
        let ciphertext = cipher.encrypt(plaintext, None).unwrap();
        let decrypted = cipher.decrypt(&ciphertext, None).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes256_with_aad() {
        let key = AesGcm256::generate_key().unwrap();
        let cipher = AesGcm256::new(&key).unwrap();

        let plaintext = b"Secret message";
        let aad = b"public header";
        let ciphertext = cipher.encrypt(plaintext, Some(aad)).unwrap();
        let decrypted = cipher.decrypt(&ciphertext, Some(aad)).unwrap();

        assert_eq!(decrypted, plaintext);

        // Wrong AAD should fail
        let result = cipher.decrypt(&ciphertext, Some(b"wrong header"));
        assert!(result.is_err());
    }

    #[test]
    fn test_aes256_invalid_key_size() {
        let result = AesGcm256::new(&[0u8; 16]);
        assert!(result.is_err());
    }

    #[test]
    fn test_aes256_tampered_ciphertext() {
        let key = AesGcm256::generate_key().unwrap();
        let cipher = AesGcm256::new(&key).unwrap();

        let plaintext = b"Secret message";
        let mut ciphertext = cipher.encrypt(plaintext, None).unwrap();

        // Tamper with ciphertext
        if !ciphertext.ciphertext.is_empty() {
            ciphertext.ciphertext[0] ^= 1;
        }

        let result = cipher.decrypt(&ciphertext, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_ciphertext_serialization() {
        let key = AesGcm256::generate_key().unwrap();
        let cipher = AesGcm256::new(&key).unwrap();

        let plaintext = b"Test message";
        let ciphertext = cipher.encrypt(plaintext, None).unwrap();

        // Serialize and deserialize
        let bytes = ciphertext.to_bytes();
        let recovered = Ciphertext::from_bytes(&bytes, 12, 16).unwrap();

        assert_eq!(ciphertext, recovered);

        // Decrypt recovered ciphertext
        let decrypted = cipher.decrypt(&recovered, None).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ciphertext_base64() {
        let ciphertext = Ciphertext::new(vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]);

        let b64 = ciphertext.to_base64();
        let recovered = Ciphertext::from_base64(&b64, 3, 3).unwrap();

        assert_eq!(ciphertext, recovered);
    }
}
