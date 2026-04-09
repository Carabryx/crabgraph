//! Streaming AEAD encryption for large files.
//!
//! This module provides streaming encryption and decryption capabilities for processing
//! large files that don't fit in memory. It uses the STREAM construction from
//! [Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance](https://eprint.iacr.org/2015/189.pdf)
//! which provides nonce-reuse resistance.
//!
//! # Security Notes
//!
//! - Each chunk is independently authenticated
//! - The stream uses a nonce derivation function to ensure unique nonces per chunk
//! - The final chunk includes authentication of the entire stream
//! - Maximum file size depends on chunk counter size (default: 2^32 chunks)
//!
//! # Example
//!
//! ```
//! use crabgraph::aead::stream::{Aes256GcmStreamEncryptor, Aes256GcmStreamDecryptor};
//! use crabgraph::CrabResult;
//!
//! # fn main() -> CrabResult<()> {
//! // Generate a 32-byte key
//! let key = crabgraph::rand::secure_bytes(32)?;
//!
//! // Encrypt data in chunks
//! let plaintext = vec![b"Hello, world! ".repeat(1000)];
//! let mut encryptor = Aes256GcmStreamEncryptor::new(&key)?;
//! let nonce = encryptor.nonce();
//! let mut ciphertext_chunks = Vec::new();
//!
//! // Encrypt all but the last chunk
//! for chunk in &plaintext[..plaintext.len() - 1] {
//!     ciphertext_chunks.push(encryptor.encrypt_next(chunk)?);
//! }
//! // Encrypt the last chunk (this consumes the encryptor)
//! let last_chunk = &plaintext[plaintext.len() - 1];
//! ciphertext_chunks.push(encryptor.encrypt_last(last_chunk)?);
//!
//! // Decrypt data in chunks
//! let mut decryptor = Aes256GcmStreamDecryptor::from_nonce(&key, &nonce)?;
//! let mut decrypted = Vec::new();
//!
//! // Decrypt all but the last chunk
//! for chunk in &ciphertext_chunks[..ciphertext_chunks.len() - 1] {
//!     decrypted.extend_from_slice(&decryptor.decrypt_next(chunk)?);
//! }
//! // Decrypt the last chunk (this consumes the decryptor)
//! let last_encrypted = &ciphertext_chunks[ciphertext_chunks.len() - 1];
//! decrypted.extend_from_slice(&decryptor.decrypt_last(last_encrypted)?);
//!
//! // Verify the decrypted data matches the first (and only) chunk in plaintext
//! assert_eq!(&decrypted, plaintext[0].as_slice());
//! # Ok(())
//! # }
//! ```

use crate::errors::{CrabError, CrabResult};
use aes_gcm::{
    aead::{
        stream::{DecryptorBE32, EncryptorBE32, Nonce as StreamNonce, StreamBE32},
        Key, KeyInit,
    },
    Aes256Gcm,
};
use chacha20poly1305::ChaCha20Poly1305 as ChaCha20Poly1305Cipher;

type AesStreamNonce = StreamNonce<Aes256Gcm, StreamBE32<Aes256Gcm>>;
type ChaChaStreamNonce = StreamNonce<ChaCha20Poly1305Cipher, StreamBE32<ChaCha20Poly1305Cipher>>;

/// Default chunk size for streaming operations (64 KB)
pub const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;

/// Maximum chunk size for streaming operations (1 MB)
pub const MAX_CHUNK_SIZE: usize = 1024 * 1024;

/// Streaming encryptor for AES-256-GCM.
///
/// Accepts raw 32-byte keys and produces a stream of encrypted chunks.
pub struct Aes256GcmStreamEncryptor {
    encryptor: EncryptorBE32<Aes256Gcm>,
    nonce: Vec<u8>,
}

impl Aes256GcmStreamEncryptor {
    /// Creates a new streaming encryptor from a 32-byte key.
    ///
    /// # Arguments
    ///
    /// * `key` - A 32-byte AES-256 key
    ///
    /// # Errors
    ///
    /// Returns an error if the key is not exactly 32 bytes.
    pub fn new(key: &[u8]) -> CrabResult<Self> {
        if key.len() != 32 {
            return Err(CrabError::invalid_input(format!(
                "AES-256 requires 32-byte key, got {}",
                key.len()
            )));
        }

        // Generate a 7-byte nonce for STREAM (AES-GCM needs 12 bytes, STREAM uses 5 for counter+flag)
        let nonce_bytes = crate::rand::secure_bytes(7)?;
        let nonce_array: &AesStreamNonce = nonce_bytes.as_slice().into();

        let key_array: &Key<Aes256Gcm> = key.into();
        let aead = Aes256Gcm::new(key_array);
        let encryptor = EncryptorBE32::from_aead(aead, nonce_array);

        Ok(Self {
            encryptor,
            nonce: nonce_bytes,
        })
    }

    /// Returns the nonce used for this stream.
    ///
    /// This nonce must be stored with the encrypted data to enable decryption.
    pub fn nonce(&self) -> Vec<u8> {
        self.nonce.clone()
    }

    /// Encrypts the next chunk of data.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The chunk of data to encrypt
    pub fn encrypt_next(&mut self, plaintext: &[u8]) -> CrabResult<Vec<u8>> {
        self.encryptor
            .encrypt_next(plaintext)
            .map_err(|e| CrabError::crypto_error(format!("Stream encryption failed: {}", e)))
    }

    /// Encrypts the last chunk and finalizes the stream.
    ///
    /// After calling this method, the encryptor cannot be used anymore.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The final chunk of data to encrypt (can be empty)
    pub fn encrypt_last(self, plaintext: &[u8]) -> CrabResult<Vec<u8>> {
        self.encryptor
            .encrypt_last(plaintext)
            .map_err(|e| CrabError::crypto_error(format!("Stream encryption failed: {}", e)))
    }
}

/// Streaming decryptor for AES-256-GCM.
pub struct Aes256GcmStreamDecryptor {
    decryptor: DecryptorBE32<Aes256Gcm>,
}

impl Aes256GcmStreamDecryptor {
    /// Creates a new streaming decryptor from a key and nonce.
    ///
    /// # Arguments
    ///
    /// * `key` - A 32-byte AES-256 key (must match the encryption key)
    /// * `nonce` - The 7-byte nonce from the encryption process
    ///
    /// # Errors
    ///
    /// Returns an error if the key or nonce have invalid lengths.
    pub fn from_nonce(key: &[u8], nonce: &[u8]) -> CrabResult<Self> {
        if key.len() != 32 {
            return Err(CrabError::invalid_input(format!(
                "AES-256 requires 32-byte key, got {}",
                key.len()
            )));
        }

        if nonce.len() != 7 {
            return Err(CrabError::invalid_input(format!(
                "Invalid nonce size for STREAM: expected 7, got {}",
                nonce.len()
            )));
        }

        let nonce_array: &AesStreamNonce = nonce.into();
        let key_array: &Key<Aes256Gcm> = key.into();
        let aead = Aes256Gcm::new(key_array);
        let decryptor = DecryptorBE32::from_aead(aead, nonce_array);

        Ok(Self {
            decryptor,
        })
    }

    /// Decrypts the next chunk of data.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The encrypted chunk (includes authentication tag)
    ///
    /// # Errors
    ///
    /// Returns an error if authentication fails or if the chunk is corrupted.
    pub fn decrypt_next(&mut self, ciphertext: &[u8]) -> CrabResult<Vec<u8>> {
        self.decryptor
            .decrypt_next(ciphertext)
            .map_err(|e| CrabError::crypto_error(format!("Stream decryption failed: {}", e)))
    }

    /// Decrypts the last chunk and finalizes the stream.
    ///
    /// After calling this method, the decryptor cannot be used anymore.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The final encrypted chunk (includes authentication tag)
    ///
    /// # Errors
    ///
    /// Returns an error if authentication fails or if the chunk is corrupted.
    pub fn decrypt_last(self, ciphertext: &[u8]) -> CrabResult<Vec<u8>> {
        self.decryptor
            .decrypt_last(ciphertext)
            .map_err(|e| CrabError::crypto_error(format!("Stream decryption failed: {}", e)))
    }
}

/// Streaming encryptor for ChaCha20-Poly1305.
///
/// Accepts raw 32-byte keys and produces a stream of encrypted chunks.
pub struct ChaCha20Poly1305StreamEncryptor {
    encryptor: EncryptorBE32<ChaCha20Poly1305Cipher>,
    nonce: Vec<u8>,
}

impl ChaCha20Poly1305StreamEncryptor {
    /// Creates a new streaming encryptor from a 32-byte key.
    ///
    /// # Arguments
    ///
    /// * `key` - A 32-byte ChaCha20-Poly1305 key
    ///
    /// # Errors
    ///
    /// Returns an error if the key is not exactly 32 bytes.
    pub fn new(key: &[u8]) -> CrabResult<Self> {
        if key.len() != 32 {
            return Err(CrabError::invalid_input(format!(
                "ChaCha20-Poly1305 requires 32-byte key, got {}",
                key.len()
            )));
        }

        // Generate a 7-byte nonce for STREAM (ChaCha20Poly1305 needs 12 bytes, STREAM uses 5 for counter+flag)
        let nonce_bytes = crate::rand::secure_bytes(7)?;
        let nonce_array: &ChaChaStreamNonce = nonce_bytes.as_slice().into();

        let key_array: &Key<ChaCha20Poly1305Cipher> = key.into();
        let aead = ChaCha20Poly1305Cipher::new(key_array);
        let encryptor = EncryptorBE32::from_aead(aead, nonce_array);

        Ok(Self {
            encryptor,
            nonce: nonce_bytes,
        })
    }

    /// Returns the nonce used for this stream.
    ///
    /// This nonce must be stored with the encrypted data to enable decryption.
    pub fn nonce(&self) -> Vec<u8> {
        self.nonce.clone()
    }

    /// Encrypts the next chunk of data.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The chunk of data to encrypt
    pub fn encrypt_next(&mut self, plaintext: &[u8]) -> CrabResult<Vec<u8>> {
        self.encryptor
            .encrypt_next(plaintext)
            .map_err(|e| CrabError::crypto_error(format!("Stream encryption failed: {}", e)))
    }

    /// Encrypts the last chunk and finalizes the stream.
    ///
    /// After calling this method, the encryptor cannot be used anymore.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The final chunk of data to encrypt (can be empty)
    pub fn encrypt_last(self, plaintext: &[u8]) -> CrabResult<Vec<u8>> {
        self.encryptor
            .encrypt_last(plaintext)
            .map_err(|e| CrabError::crypto_error(format!("Stream encryption failed: {}", e)))
    }
}

/// Streaming decryptor for ChaCha20-Poly1305.
pub struct ChaCha20Poly1305StreamDecryptor {
    decryptor: DecryptorBE32<ChaCha20Poly1305Cipher>,
}

impl ChaCha20Poly1305StreamDecryptor {
    /// Creates a new streaming decryptor from a key and nonce.
    ///
    /// # Arguments
    ///
    /// * `key` - A 32-byte ChaCha20-Poly1305 key (must match the encryption key)
    /// * `nonce` - The 7-byte nonce from the encryption process
    ///
    /// # Errors
    ///
    /// Returns an error if the key or nonce have invalid lengths.
    pub fn from_nonce(key: &[u8], nonce: &[u8]) -> CrabResult<Self> {
        if key.len() != 32 {
            return Err(CrabError::invalid_input(format!(
                "ChaCha20-Poly1305 requires 32-byte key, got {}",
                key.len()
            )));
        }

        if nonce.len() != 7 {
            return Err(CrabError::invalid_input(format!(
                "Invalid nonce size for STREAM: expected 7, got {}",
                nonce.len()
            )));
        }

        let nonce_array: &ChaChaStreamNonce = nonce.into();
        let key_array: &Key<ChaCha20Poly1305Cipher> = key.into();
        let aead = ChaCha20Poly1305Cipher::new(key_array);
        let decryptor = DecryptorBE32::from_aead(aead, nonce_array);

        Ok(Self {
            decryptor,
        })
    }

    /// Decrypts the next chunk of data.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The encrypted chunk (includes authentication tag)
    ///
    /// # Errors
    ///
    /// Returns an error if authentication fails or if the chunk is corrupted.
    pub fn decrypt_next(&mut self, ciphertext: &[u8]) -> CrabResult<Vec<u8>> {
        self.decryptor
            .decrypt_next(ciphertext)
            .map_err(|e| CrabError::crypto_error(format!("Stream decryption failed: {}", e)))
    }

    /// Decrypts the last chunk and finalizes the stream.
    ///
    /// After calling this method, the decryptor cannot be used anymore.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The final encrypted chunk (includes authentication tag)
    ///
    /// # Errors
    ///
    /// Returns an error if authentication fails or if the chunk is corrupted.
    pub fn decrypt_last(self, ciphertext: &[u8]) -> CrabResult<Vec<u8>> {
        self.decryptor
            .decrypt_last(ciphertext)
            .map_err(|e| CrabError::crypto_error(format!("Stream decryption failed: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes256gcm_stream_encrypt_decrypt() -> CrabResult<()> {
        let key = crate::rand::secure_bytes(32)?;
        let plaintext_chunks = vec![b"Hello, ".as_slice(), b"world!".as_slice()];

        // Encrypt
        let mut encryptor = Aes256GcmStreamEncryptor::new(&key)?;
        let nonce = encryptor.nonce();

        let mut ciphertext_chunks = Vec::new();
        for chunk in &plaintext_chunks {
            ciphertext_chunks.push(encryptor.encrypt_next(chunk)?);
        }
        ciphertext_chunks.push(encryptor.encrypt_last(b"")?);

        // Decrypt
        let mut decryptor = Aes256GcmStreamDecryptor::from_nonce(&key, &nonce)?;
        let mut decrypted = Vec::new();

        let last_idx = ciphertext_chunks.len() - 1;
        for (i, chunk) in ciphertext_chunks.iter().enumerate() {
            if i == last_idx {
                decrypted.extend_from_slice(&decryptor.decrypt_last(chunk)?);
                break; // Decryptor is consumed, no more iterations
            } else {
                decrypted.extend_from_slice(&decryptor.decrypt_next(chunk)?);
            }
        }

        let expected: Vec<u8> = plaintext_chunks.concat();
        assert_eq!(decrypted, expected);

        Ok(())
    }

    #[test]
    fn test_chacha20poly1305_stream_encrypt_decrypt() -> CrabResult<()> {
        let key = crate::rand::secure_bytes(32)?;
        let plaintext_chunks = vec![b"First chunk".as_slice(), b"Second chunk".as_slice()];

        // Encrypt
        let mut encryptor = ChaCha20Poly1305StreamEncryptor::new(&key)?;
        let nonce = encryptor.nonce();

        let mut ciphertext_chunks = Vec::new();
        for chunk in &plaintext_chunks {
            ciphertext_chunks.push(encryptor.encrypt_next(chunk)?);
        }
        ciphertext_chunks.push(encryptor.encrypt_last(b"Final chunk")?);

        // Decrypt
        let mut decryptor = ChaCha20Poly1305StreamDecryptor::from_nonce(&key, &nonce)?;
        let mut decrypted = Vec::new();

        let last_idx = ciphertext_chunks.len() - 1;
        for (i, chunk) in ciphertext_chunks.iter().enumerate() {
            if i == last_idx {
                decrypted.extend_from_slice(&decryptor.decrypt_last(chunk)?);
                break; // Decryptor is consumed, no more iterations
            } else {
                decrypted.extend_from_slice(&decryptor.decrypt_next(chunk)?);
            }
        }

        let mut expected: Vec<u8> = plaintext_chunks.concat();
        expected.extend_from_slice(b"Final chunk");
        assert_eq!(decrypted, expected);

        Ok(())
    }

    #[test]
    fn test_stream_large_data() -> CrabResult<()> {
        let key = crate::rand::secure_bytes(32)?;
        let chunk_size = 1024;
        let num_chunks = 100;

        // Generate large plaintext
        let mut plaintext = Vec::new();
        for i in 0..num_chunks {
            plaintext.extend_from_slice(&vec![i as u8; chunk_size]);
        }

        // Encrypt in chunks
        let mut encryptor = Aes256GcmStreamEncryptor::new(&key)?;
        let nonce = encryptor.nonce();

        let mut ciphertext_chunks = Vec::new();
        for chunk in plaintext.chunks(chunk_size) {
            ciphertext_chunks.push(encryptor.encrypt_next(chunk)?);
        }
        ciphertext_chunks.push(encryptor.encrypt_last(&[])?);

        // Decrypt in chunks
        let mut decryptor = Aes256GcmStreamDecryptor::from_nonce(&key, &nonce)?;
        let mut decrypted = Vec::new();

        let last_idx = ciphertext_chunks.len() - 1;
        for (i, chunk) in ciphertext_chunks.iter().enumerate() {
            if i == last_idx {
                decrypted.extend_from_slice(&decryptor.decrypt_last(chunk)?);
                break; // Decryptor is consumed, no more iterations
            } else {
                decrypted.extend_from_slice(&decryptor.decrypt_next(chunk)?);
            }
        }

        assert_eq!(decrypted, plaintext);

        Ok(())
    }

    #[test]
    fn test_stream_authentication_failure() -> CrabResult<()> {
        let key = crate::rand::secure_bytes(32)?;

        // Encrypt
        let mut encryptor = Aes256GcmStreamEncryptor::new(&key)?;
        let nonce = encryptor.nonce();

        let chunk1 = encryptor.encrypt_next(b"Hello")?;
        let mut chunk2 = encryptor.encrypt_last(b"World")?;

        // Corrupt the second chunk
        chunk2[0] ^= 1;

        // Decrypt
        let mut decryptor = Aes256GcmStreamDecryptor::from_nonce(&key, &nonce)?;
        decryptor.decrypt_next(&chunk1)?;

        // Should fail authentication
        let result = decryptor.decrypt_last(&chunk2);
        assert!(result.is_err());

        Ok(())
    }

    #[test]
    fn test_stream_empty_chunks() -> CrabResult<()> {
        let key = crate::rand::secure_bytes(32)?;

        // Encrypt empty data
        let encryptor = Aes256GcmStreamEncryptor::new(&key)?;
        let nonce = encryptor.nonce();

        let chunk = encryptor.encrypt_last(b"")?;

        // Decrypt
        let decryptor = Aes256GcmStreamDecryptor::from_nonce(&key, &nonce)?;
        let decrypted = decryptor.decrypt_last(&chunk)?;

        assert_eq!(decrypted, b"");

        Ok(())
    }
}
