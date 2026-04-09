//! Authenticated Encryption with Associated Data (AEAD).
//!
//! This module provides high-level, safe-by-default AEAD ciphers.

pub mod aead_trait;
pub mod aes_gcm;
pub mod chacha20poly1305;
pub mod stream;

pub use aead_trait::CrabAead;
pub use aes_gcm::{AesGcm128, AesGcm256};
pub use chacha20poly1305::ChaCha20Poly1305;

/// Result of an AEAD encryption operation.
///
/// Contains the nonce, ciphertext, and authentication tag in a single structure.
/// Can be serialized to/from bytes for storage or transmission.
///
/// With the `serde-support` feature, this type can be serialized to JSON/TOML.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde-support", derive(serde::Serialize, serde::Deserialize))]
pub struct Ciphertext {
    /// Nonce/IV used for this encryption (12 bytes for AES-GCM and ChaCha20-Poly1305)
    #[cfg_attr(feature = "serde-support", serde(with = "serde_bytes_base64"))]
    pub nonce: Vec<u8>,
    /// Encrypted data
    #[cfg_attr(feature = "serde-support", serde(with = "serde_bytes_base64"))]
    pub ciphertext: Vec<u8>,
    /// Authentication tag (16 bytes)
    #[cfg_attr(feature = "serde-support", serde(with = "serde_bytes_base64"))]
    pub tag: Vec<u8>,
}

#[cfg(feature = "serde-support")]
mod serde_bytes_base64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&crate::encoding::base64_encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        crate::encoding::base64_decode(&s).map_err(serde::de::Error::custom)
    }
}

impl Ciphertext {
    /// Creates a new `Ciphertext` from components.
    pub fn new(nonce: Vec<u8>, ciphertext: Vec<u8>, tag: Vec<u8>) -> Self {
        Self {
            nonce,
            ciphertext,
            tag,
        }
    }

    /// Serializes to bytes: nonce || ciphertext || tag
    ///
    /// # Example
    /// ```
    /// use crabgraph::aead::{AesGcm256, CrabAead};
    ///
    /// let key = AesGcm256::generate_key().unwrap();
    /// let cipher = AesGcm256::new(&key).unwrap();
    /// let ciphertext = cipher.encrypt(b"secret", None).unwrap();
    ///
    /// let bytes = ciphertext.to_bytes();
    /// let recovered = crabgraph::aead::Ciphertext::from_bytes(&bytes, 12, 16).unwrap();
    /// assert_eq!(ciphertext, recovered);
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result =
            Vec::with_capacity(self.nonce.len() + self.ciphertext.len() + self.tag.len());
        result.extend_from_slice(&self.nonce);
        result.extend_from_slice(&self.ciphertext);
        result.extend_from_slice(&self.tag);
        result
    }

    /// Deserializes from bytes: nonce || ciphertext || tag
    ///
    /// # Arguments
    /// * `data` - Serialized ciphertext bytes
    /// * `nonce_len` - Expected nonce length (typically 12)
    /// * `tag_len` - Expected tag length (typically 16)
    ///
    /// # Errors
    /// Returns error if data is too short or malformed.
    pub fn from_bytes(
        data: &[u8],
        nonce_len: usize,
        tag_len: usize,
    ) -> crate::errors::CrabResult<Self> {
        use crate::errors::CrabError;

        if data.len() < nonce_len + tag_len {
            return Err(CrabError::invalid_input(format!(
                "Ciphertext too short: expected at least {} bytes, got {}",
                nonce_len + tag_len,
                data.len()
            )));
        }

        let nonce = data[..nonce_len].to_vec();
        let ciphertext = data[nonce_len..data.len() - tag_len].to_vec();
        let tag = data[data.len() - tag_len..].to_vec();

        Ok(Self::new(nonce, ciphertext, tag))
    }

    /// Encodes to base64 string.
    pub fn to_base64(&self) -> String {
        crate::encoding::base64_encode(&self.to_bytes())
    }

    /// Decodes from base64 string.
    pub fn from_base64(
        data: &str,
        nonce_len: usize,
        tag_len: usize,
    ) -> crate::errors::CrabResult<Self> {
        let bytes = crate::encoding::base64_decode(data)?;
        Self::from_bytes(&bytes, nonce_len, tag_len)
    }
}
