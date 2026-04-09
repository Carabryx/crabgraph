//! Key rotation and versioning utilities.
//!
//! This module provides tools for managing cryptographic key rotation, a critical
//! security practice where keys are periodically replaced to limit exposure from
//! potential key compromise.
//!
//! # Features
//!
//! - **Key Versioning**: Track which version of a key encrypted each piece of data
//! - **Multiple Key Storage**: Securely store multiple key versions simultaneously
//! - **Automatic Re-encryption**: Utilities to decrypt with old keys and encrypt with new ones
//! - **Zero-downtime Rotation**: Support for gradual key transitions without service interruption
//!
//! # Security Considerations
//!
//! - Old keys should be retained only as long as needed for re-encryption
//! - Set a maximum number of key versions to prevent unbounded growth
//! - Implement a key deletion policy after successful re-encryption
//! - Audit key usage to ensure old keys are eventually phased out
//! - Use secure key storage (HSM, KMS) for production deployments
//!
//! # Example
//!
//! ```
//! use crabgraph::{
//!     key_rotation::KeyRotationManager,
//!     aead::{AesGcm256, CrabAead},
//!     CrabResult,
//! };
//!
//! fn rotation_example() -> CrabResult<()> {
//!     // Create a key rotation manager
//!     let mut manager = KeyRotationManager::<AesGcm256>::new()?;
//!     
//!     // Encrypt data with version 1 key
//!     let data = b"Secret data";
//!     let (version, ciphertext) = manager.encrypt(data, None)?;
//!     assert_eq!(version, 1);
//!     
//!     // Rotate to a new key (version 2)
//!     manager.rotate()?;
//!     
//!     // Can still decrypt old data with version 1
//!     let decrypted = manager.decrypt(version, &ciphertext, None)?;
//!     assert_eq!(decrypted, data);
//!     
//!     // Re-encrypt old data with the new key
//!     let (new_version, new_ciphertext) = manager.re_encrypt(version, &ciphertext, None)?;
//!     assert_eq!(new_version, 2);
//!     
//!     Ok(())
//! }
//! ```

use crate::{
    aead::{Ciphertext, CrabAead},
    errors::{CrabError, CrabResult},
    secrets::SecretVec,
};
use std::collections::HashMap;
use zeroize::Zeroize;

/// Trait for AEAD ciphers that support key generation and creation.
///
/// This extends `CrabAead` with methods needed for key rotation.
pub trait RotatableAead: CrabAead {
    /// Generate a new random key for this cipher.
    fn generate_key() -> CrabResult<SecretVec>;

    /// Create a new cipher instance from a key.
    fn from_key(key: &SecretVec) -> CrabResult<Self>
    where
        Self: Sized;
}

/// A versioned cryptographic key.
///
/// Wraps a key with version information to track which version was used
/// for encryption operations.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct VersionedKey {
    /// The version number (starts at 1)
    pub version: u32,
    /// The actual key material (auto-zeroized on drop)
    pub key: SecretVec,
}

impl VersionedKey {
    /// Create a new versioned key.
    ///
    /// # Arguments
    ///
    /// * `version` - The version number (must be >= 1)
    /// * `key` - The key material
    ///
    /// # Errors
    ///
    /// Returns `CrabError::InvalidInput` if version is 0.
    pub fn new(version: u32, key: SecretVec) -> CrabResult<Self> {
        if version == 0 {
            return Err(CrabError::invalid_input("Key version must be >= 1"));
        }
        Ok(Self {
            version,
            key,
        })
    }

    /// Get the version number.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Get a reference to the key material.
    pub fn key(&self) -> &SecretVec {
        &self.key
    }
}

/// Manager for cryptographic key rotation.
///
/// Maintains multiple versions of keys and provides utilities for encrypting with
/// the current key, decrypting with any version, and re-encrypting data from old
/// to new keys.
///
/// # Type Parameters
///
/// * `C` - The AEAD cipher type (e.g., `AesGcm256`, `ChaCha20Poly1305`)
///
/// # Security Notes
///
/// - Keys are stored in memory using `SecretVec` (auto-zeroized on drop)
/// - Maximum 256 key versions by default (prevents unbounded memory growth)
/// - Old keys should be removed after successful re-encryption
/// - Consider using HSM/KMS for production key storage
///
/// # Example
///
/// ```
/// use crabgraph::{
///     key_rotation::KeyRotationManager,
///     aead::ChaCha20Poly1305,
///     CrabResult,
/// };
///
/// fn example() -> CrabResult<()> {
///     let mut manager = KeyRotationManager::<ChaCha20Poly1305>::new()?;
///     
///     // Encrypt with current key (version 1)
///     let (v1, ct1) = manager.encrypt(b"data1", None)?;
///     
///     // Rotate to version 2
///     manager.rotate()?;
///     let (v2, ct2) = manager.encrypt(b"data2", None)?;
///     
///     // Both versions can decrypt their data
///     assert_eq!(manager.decrypt(v1, &ct1, None)?, b"data1");
///     assert_eq!(manager.decrypt(v2, &ct2, None)?, b"data2");
///     
///     // Re-encrypt old data with new key
///     let (v2_new, ct1_new) = manager.re_encrypt(v1, &ct1, None)?;
///     assert_eq!(v2_new, v2);
///     
///     Ok(())
/// }
/// ```
pub struct KeyRotationManager<C: RotatableAead> {
    /// All key versions (version number -> key)
    keys: HashMap<u32, SecretVec>,
    /// Current (latest) key version
    current_version: u32,
    /// Maximum number of versions to keep
    max_versions: usize,
    /// Phantom data for the cipher type
    _phantom: std::marker::PhantomData<C>,
}

impl<C: RotatableAead> KeyRotationManager<C> {
    /// Create a new key rotation manager with an initial key.
    ///
    /// Generates a random key as version 1.
    ///
    /// # Errors
    ///
    /// Returns an error if key generation fails.
    ///
    /// # Example
    ///
    /// ```
    /// use crabgraph::{key_rotation::KeyRotationManager, aead::AesGcm256, CrabResult};
    ///
    /// fn example() -> CrabResult<()> {
    ///     let manager = KeyRotationManager::<AesGcm256>::new()?;
    ///     assert_eq!(manager.current_version(), 1);
    ///     Ok(())
    /// }
    /// ```
    pub fn new() -> CrabResult<Self> {
        Self::with_max_versions(256)
    }

    /// Create a new key rotation manager with a specified maximum number of versions.
    ///
    /// # Arguments
    ///
    /// * `max_versions` - Maximum number of key versions to retain (must be >= 1)
    ///
    /// # Errors
    ///
    /// Returns `CrabError::InvalidInput` if `max_versions` is 0.
    ///
    /// # Example
    ///
    /// ```
    /// use crabgraph::{key_rotation::KeyRotationManager, aead::AesGcm256, CrabResult};
    ///
    /// fn example() -> CrabResult<()> {
    ///     // Keep only last 10 key versions
    ///     let manager = KeyRotationManager::<AesGcm256>::with_max_versions(10)?;
    ///     Ok(())
    /// }
    /// ```
    pub fn with_max_versions(max_versions: usize) -> CrabResult<Self> {
        if max_versions == 0 {
            return Err(CrabError::invalid_input("max_versions must be >= 1"));
        }

        let key = C::generate_key()?;
        let mut keys = HashMap::new();
        keys.insert(1, key);

        Ok(Self {
            keys,
            current_version: 1,
            max_versions,
            _phantom: std::marker::PhantomData,
        })
    }

    /// Create a manager from an existing key as version 1.
    ///
    /// Useful when you have an existing key to manage.
    ///
    /// # Arguments
    ///
    /// * `key` - The initial key
    ///
    /// # Example
    ///
    /// ```
    /// use crabgraph::{
    ///     key_rotation::KeyRotationManager,
    ///     aead::{AesGcm256, CrabAead},
    ///     secrets::SecretVec,
    ///     CrabResult,
    /// };
    ///
    /// fn example() -> CrabResult<()> {
    ///     let existing_key_bytes = AesGcm256::generate_key()?;
    ///     let existing_key = SecretVec::new(existing_key_bytes);
    ///     let manager = KeyRotationManager::<AesGcm256>::from_key(existing_key)?;
    ///     Ok(())
    /// }
    /// ```
    pub fn from_key(key: SecretVec) -> CrabResult<Self> {
        let mut keys = HashMap::new();
        keys.insert(1, key);

        Ok(Self {
            keys,
            current_version: 1,
            max_versions: 256,
            _phantom: std::marker::PhantomData,
        })
    }

    /// Rotate to a new key version.
    ///
    /// Generates a new random key and increments the version number.
    /// Old keys are retained for decryption.
    ///
    /// If the number of versions exceeds `max_versions`, the oldest key is removed.
    ///
    /// # Errors
    ///
    /// Returns an error if key generation fails or if version would overflow.
    ///
    /// # Example
    ///
    /// ```
    /// use crabgraph::{key_rotation::KeyRotationManager, aead::AesGcm256, CrabResult};
    ///
    /// fn example() -> CrabResult<()> {
    ///     let mut manager = KeyRotationManager::<AesGcm256>::new()?;
    ///     assert_eq!(manager.current_version(), 1);
    ///     
    ///     manager.rotate()?;
    ///     assert_eq!(manager.current_version(), 2);
    ///     
    ///     Ok(())
    /// }
    /// ```
    pub fn rotate(&mut self) -> CrabResult<()> {
        let new_version = self
            .current_version
            .checked_add(1)
            .ok_or_else(|| CrabError::invalid_input("Version number overflow"))?;

        let new_key = C::generate_key()?;
        self.keys.insert(new_version, new_key);
        self.current_version = new_version;

        // Remove oldest key if exceeding max_versions
        if self.keys.len() > self.max_versions {
            let oldest_version = self.current_version - self.max_versions as u32;
            self.keys.remove(&oldest_version);
        }

        Ok(())
    }

    /// Rotate to a new key version using a provided key.
    ///
    /// Similar to `rotate()`, but uses a specific key instead of generating a random one.
    ///
    /// # Arguments
    ///
    /// * `key` - The new key to use
    ///
    /// # Errors
    ///
    /// Returns an error if version would overflow.
    pub fn rotate_with_key(&mut self, key: SecretVec) -> CrabResult<()> {
        let new_version = self
            .current_version
            .checked_add(1)
            .ok_or_else(|| CrabError::invalid_input("Version number overflow"))?;

        self.keys.insert(new_version, key);
        self.current_version = new_version;

        // Remove oldest key if exceeding max_versions
        if self.keys.len() > self.max_versions {
            let oldest_version = self.current_version - self.max_versions as u32;
            self.keys.remove(&oldest_version);
        }

        Ok(())
    }

    /// Get the current (latest) key version number.
    ///
    /// # Example
    ///
    /// ```
    /// use crabgraph::{key_rotation::KeyRotationManager, aead::AesGcm256, CrabResult};
    ///
    /// fn example() -> CrabResult<()> {
    ///     let manager = KeyRotationManager::<AesGcm256>::new()?;
    ///     println!("Current version: {}", manager.current_version());
    ///     Ok(())
    /// }
    /// ```
    pub fn current_version(&self) -> u32 {
        self.current_version
    }

    /// Get the number of key versions currently stored.
    pub fn version_count(&self) -> usize {
        self.keys.len()
    }

    /// Check if a specific key version exists.
    ///
    /// # Arguments
    ///
    /// * `version` - The version to check
    pub fn has_version(&self, version: u32) -> bool {
        self.keys.contains_key(&version)
    }

    /// Encrypt data with the current (latest) key version.
    ///
    /// Returns the version number and ciphertext.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - Data to encrypt
    /// * `aad` - Optional associated data (authenticated but not encrypted)
    ///
    /// # Returns
    ///
    /// A tuple of `(version, ciphertext)` where version is the key version used.
    ///
    /// # Errors
    ///
    /// Returns an error if encryption fails.
    ///
    /// # Example
    ///
    /// ```
    /// use crabgraph::{key_rotation::KeyRotationManager, aead::AesGcm256, CrabResult};
    ///
    /// fn example() -> CrabResult<()> {
    ///     let manager = KeyRotationManager::<AesGcm256>::new()?;
    ///     let (version, ciphertext) = manager.encrypt(b"secret data", None)?;
    ///     println!("Encrypted with key version {}", version);
    ///     Ok(())
    /// }
    /// ```
    pub fn encrypt(&self, plaintext: &[u8], aad: Option<&[u8]>) -> CrabResult<(u32, Ciphertext)> {
        let key = self
            .keys
            .get(&self.current_version)
            .ok_or_else(|| CrabError::invalid_input("Current key version not found"))?;

        let cipher = C::from_key(key)?;
        let ciphertext = cipher.encrypt(plaintext, aad)?;

        Ok((self.current_version, ciphertext))
    }

    /// Decrypt data using a specific key version.
    ///
    /// # Arguments
    ///
    /// * `version` - The key version to use for decryption
    /// * `ciphertext` - The encrypted data
    /// * `aad` - Optional associated data (must match what was used during encryption)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The specified version doesn't exist
    /// - Decryption fails (wrong key, tampered data, etc.)
    ///
    /// # Example
    ///
    /// ```
    /// use crabgraph::{key_rotation::KeyRotationManager, aead::AesGcm256, CrabResult};
    ///
    /// fn example() -> CrabResult<()> {
    ///     let manager = KeyRotationManager::<AesGcm256>::new()?;
    ///     let (version, ciphertext) = manager.encrypt(b"secret", None)?;
    ///     let plaintext = manager.decrypt(version, &ciphertext, None)?;
    ///     assert_eq!(plaintext, b"secret");
    ///     Ok(())
    /// }
    /// ```
    pub fn decrypt(
        &self,
        version: u32,
        ciphertext: &Ciphertext,
        aad: Option<&[u8]>,
    ) -> CrabResult<Vec<u8>> {
        let key = self.keys.get(&version).ok_or_else(|| {
            CrabError::invalid_input(format!("Key version {} not found", version))
        })?;

        let cipher = C::from_key(key)?;
        cipher.decrypt(ciphertext, aad)
    }

    /// Re-encrypt data from an old key version to the current version.
    ///
    /// This is the core utility for key rotation: it decrypts data with an old key
    /// and re-encrypts it with the current key in a single operation.
    ///
    /// # Arguments
    ///
    /// * `old_version` - The version that was used to encrypt the data
    /// * `old_ciphertext` - The data encrypted with the old key
    /// * `aad` - Optional associated data (must match original encryption)
    ///
    /// # Returns
    ///
    /// A tuple of `(new_version, new_ciphertext)` encrypted with the current key.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The old version doesn't exist
    /// - Decryption with old key fails
    /// - Encryption with new key fails
    ///
    /// # Example
    ///
    /// ```
    /// use crabgraph::{key_rotation::KeyRotationManager, aead::AesGcm256, CrabResult};
    ///
    /// fn example() -> CrabResult<()> {
    ///     let mut manager = KeyRotationManager::<AesGcm256>::new()?;
    ///     
    ///     // Encrypt with version 1
    ///     let (v1, ct1) = manager.encrypt(b"data", None)?;
    ///     
    ///     // Rotate to version 2
    ///     manager.rotate()?;
    ///     
    ///     // Re-encrypt from v1 to v2
    ///     let (v2, ct2) = manager.re_encrypt(v1, &ct1, None)?;
    ///     assert_eq!(v2, 2);
    ///     
    ///     // Verify new ciphertext decrypts correctly
    ///     let plaintext = manager.decrypt(v2, &ct2, None)?;
    ///     assert_eq!(plaintext, b"data");
    ///     
    ///     Ok(())
    /// }
    /// ```
    pub fn re_encrypt(
        &self,
        old_version: u32,
        old_ciphertext: &Ciphertext,
        aad: Option<&[u8]>,
    ) -> CrabResult<(u32, Ciphertext)> {
        // Decrypt with old key
        let plaintext = self.decrypt(old_version, old_ciphertext, aad)?;

        // Encrypt with current key
        self.encrypt(&plaintext, aad)
    }

    /// Remove a specific key version.
    ///
    /// Use this after successfully re-encrypting all data that used this version.
    ///
    /// # Arguments
    ///
    /// * `version` - The version to remove
    ///
    /// # Errors
    ///
    /// Returns an error if trying to remove the current version.
    ///
    /// # Security Note
    ///
    /// Ensure all data encrypted with this version has been re-encrypted before removal,
    /// otherwise it will become unrecoverable.
    ///
    /// # Example
    ///
    /// ```
    /// use crabgraph::{key_rotation::KeyRotationManager, aead::AesGcm256, CrabResult};
    ///
    /// fn example() -> CrabResult<()> {
    ///     let mut manager = KeyRotationManager::<AesGcm256>::new()?;
    ///     manager.rotate()?;  // Now at version 2
    ///     
    ///     // After re-encrypting all v1 data...
    ///     manager.remove_version(1)?;
    ///     
    ///     assert!(!manager.has_version(1));
    ///     assert!(manager.has_version(2));
    ///     
    ///     Ok(())
    /// }
    /// ```
    pub fn remove_version(&mut self, version: u32) -> CrabResult<()> {
        if version == self.current_version {
            return Err(CrabError::invalid_input("Cannot remove current key version"));
        }

        self.keys.remove(&version);
        Ok(())
    }

    /// Get a list of all key versions currently available.
    ///
    /// Returns versions in ascending order.
    ///
    /// # Example
    ///
    /// ```
    /// use crabgraph::{key_rotation::KeyRotationManager, aead::AesGcm256, CrabResult};
    ///
    /// fn example() -> CrabResult<()> {
    ///     let mut manager = KeyRotationManager::<AesGcm256>::new()?;
    ///     manager.rotate()?;
    ///     manager.rotate()?;
    ///     
    ///     let versions = manager.available_versions();
    ///     assert_eq!(versions, vec![1, 2, 3]);
    ///     
    ///     Ok(())
    /// }
    /// ```
    pub fn available_versions(&self) -> Vec<u32> {
        let mut versions: Vec<u32> = self.keys.keys().copied().collect();
        versions.sort_unstable();
        versions
    }
}

// Implement Drop to ensure keys are zeroized
impl<C: RotatableAead> Drop for KeyRotationManager<C> {
    fn drop(&mut self) {
        // SecretVec handles zeroization automatically
        self.keys.clear();
    }
}

// Implement RotatableAead for AesGcm256
impl RotatableAead for crate::aead::AesGcm256 {
    fn generate_key() -> CrabResult<SecretVec> {
        let key_bytes = crate::aead::AesGcm256::generate_key()?;
        Ok(SecretVec::new(key_bytes))
    }

    fn from_key(key: &SecretVec) -> CrabResult<Self> {
        crate::aead::AesGcm256::new(key.as_ref())
    }
}

// Implement RotatableAead for ChaCha20Poly1305
impl RotatableAead for crate::aead::ChaCha20Poly1305 {
    fn generate_key() -> CrabResult<SecretVec> {
        let key_bytes = crate::aead::ChaCha20Poly1305::generate_key()?;
        Ok(SecretVec::new(key_bytes))
    }

    fn from_key(key: &SecretVec) -> CrabResult<Self> {
        crate::aead::ChaCha20Poly1305::new(key.as_ref())
    }
}

// Implement RotatableAead for AesGcm128
impl RotatableAead for crate::aead::AesGcm128 {
    fn generate_key() -> CrabResult<SecretVec> {
        let key_bytes = crate::aead::AesGcm128::generate_key()?;
        Ok(SecretVec::new(key_bytes))
    }

    fn from_key(key: &SecretVec) -> CrabResult<Self> {
        crate::aead::AesGcm128::new(key.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aead::{AesGcm256, ChaCha20Poly1305};

    #[test]
    fn test_versioned_key_creation() {
        let key = SecretVec::new(vec![1u8; 32]);
        let vkey = VersionedKey::new(1, key).unwrap();
        assert_eq!(vkey.version(), 1);
        assert_eq!(vkey.key().as_ref().len(), 32);
    }

    #[test]
    fn test_versioned_key_zero_version_fails() {
        let key = SecretVec::new(vec![1u8; 32]);
        let result = VersionedKey::new(0, key);
        assert!(result.is_err());
    }

    #[test]
    fn test_key_rotation_manager_new() {
        let manager = KeyRotationManager::<AesGcm256>::new().unwrap();
        assert_eq!(manager.current_version(), 1);
        assert_eq!(manager.version_count(), 1);
        assert!(manager.has_version(1));
    }

    #[test]
    fn test_rotation() {
        let mut manager = KeyRotationManager::<AesGcm256>::new().unwrap();
        assert_eq!(manager.current_version(), 1);

        manager.rotate().unwrap();
        assert_eq!(manager.current_version(), 2);
        assert_eq!(manager.version_count(), 2);

        manager.rotate().unwrap();
        assert_eq!(manager.current_version(), 3);
        assert_eq!(manager.version_count(), 3);
    }

    #[test]
    fn test_encrypt_decrypt_with_version() {
        let manager = KeyRotationManager::<AesGcm256>::new().unwrap();
        let plaintext = b"Secret message";

        let (version, ciphertext) = manager.encrypt(plaintext, None).unwrap();
        assert_eq!(version, 1);

        let decrypted = manager.decrypt(version, &ciphertext, None).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_with_aad() {
        let manager = KeyRotationManager::<ChaCha20Poly1305>::new().unwrap();
        let plaintext = b"Secret message";
        let aad = b"metadata";

        let (version, ciphertext) = manager.encrypt(plaintext, Some(aad)).unwrap();
        let decrypted = manager.decrypt(version, &ciphertext, Some(aad)).unwrap();
        assert_eq!(decrypted, plaintext);

        // Wrong AAD should fail
        let result = manager.decrypt(version, &ciphertext, Some(b"wrong"));
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_with_old_version() {
        let mut manager = KeyRotationManager::<AesGcm256>::new().unwrap();

        // Encrypt with v1
        let plaintext1 = b"Message 1";
        let (v1, ct1) = manager.encrypt(plaintext1, None).unwrap();
        assert_eq!(v1, 1);

        // Rotate to v2
        manager.rotate().unwrap();

        // Encrypt with v2
        let plaintext2 = b"Message 2";
        let (v2, ct2) = manager.encrypt(plaintext2, None).unwrap();
        assert_eq!(v2, 2);

        // Both should decrypt correctly
        assert_eq!(manager.decrypt(v1, &ct1, None).unwrap(), plaintext1);
        assert_eq!(manager.decrypt(v2, &ct2, None).unwrap(), plaintext2);
    }

    #[test]
    fn test_re_encrypt() {
        let mut manager = KeyRotationManager::<AesGcm256>::new().unwrap();

        // Encrypt with v1
        let plaintext = b"Important data";
        let (v1, ct1) = manager.encrypt(plaintext, None).unwrap();
        assert_eq!(v1, 1);

        // Rotate to v2
        manager.rotate().unwrap();

        // Re-encrypt from v1 to v2
        let (v2, ct2) = manager.re_encrypt(v1, &ct1, None).unwrap();
        assert_eq!(v2, 2);

        // New ciphertext should decrypt correctly
        let decrypted = manager.decrypt(v2, &ct2, None).unwrap();
        assert_eq!(decrypted, plaintext);

        // Old ciphertext should still work
        let decrypted_old = manager.decrypt(v1, &ct1, None).unwrap();
        assert_eq!(decrypted_old, plaintext);
    }

    #[test]
    fn test_re_encrypt_with_aad() {
        let mut manager = KeyRotationManager::<ChaCha20Poly1305>::new().unwrap();
        let plaintext = b"Data";
        let aad = b"context";

        let (v1, ct1) = manager.encrypt(plaintext, Some(aad)).unwrap();
        manager.rotate().unwrap();

        let (v2, ct2) = manager.re_encrypt(v1, &ct1, Some(aad)).unwrap();
        assert_eq!(v2, 2);

        let decrypted = manager.decrypt(v2, &ct2, Some(aad)).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_remove_version() {
        let mut manager = KeyRotationManager::<AesGcm256>::new().unwrap();
        manager.rotate().unwrap(); // v2

        assert!(manager.has_version(1));
        manager.remove_version(1).unwrap();
        assert!(!manager.has_version(1));
        assert!(manager.has_version(2));
    }

    #[test]
    fn test_cannot_remove_current_version() {
        let mut manager = KeyRotationManager::<AesGcm256>::new().unwrap();
        let result = manager.remove_version(1);
        assert!(result.is_err());
    }

    #[test]
    fn test_max_versions() {
        let mut manager = KeyRotationManager::<AesGcm256>::with_max_versions(3).unwrap();

        manager.rotate().unwrap(); // v2
        manager.rotate().unwrap(); // v3
        assert_eq!(manager.version_count(), 3);

        manager.rotate().unwrap(); // v4, should remove v1
        assert_eq!(manager.version_count(), 3);
        assert!(!manager.has_version(1));
        assert!(manager.has_version(2));
        assert!(manager.has_version(3));
        assert!(manager.has_version(4));
    }

    #[test]
    fn test_available_versions() {
        let mut manager = KeyRotationManager::<AesGcm256>::new().unwrap();
        manager.rotate().unwrap();
        manager.rotate().unwrap();

        let versions = manager.available_versions();
        assert_eq!(versions, vec![1, 2, 3]);
    }

    #[test]
    fn test_from_existing_key() {
        let key_bytes = AesGcm256::generate_key().unwrap();
        let key = SecretVec::new(key_bytes);
        let manager = KeyRotationManager::<AesGcm256>::from_key(key).unwrap();
        assert_eq!(manager.current_version(), 1);

        let (version, ciphertext) = manager.encrypt(b"test", None).unwrap();
        assert_eq!(version, 1);
        assert!(manager.decrypt(version, &ciphertext, None).is_ok());
    }

    #[test]
    fn test_decrypt_nonexistent_version() {
        let manager = KeyRotationManager::<AesGcm256>::new().unwrap();
        let (_, ciphertext) = manager.encrypt(b"test", None).unwrap();

        let result = manager.decrypt(999, &ciphertext, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_rotate_with_key() {
        let mut manager = KeyRotationManager::<AesGcm256>::new().unwrap();
        let custom_key_bytes = AesGcm256::generate_key().unwrap();
        let custom_key = SecretVec::new(custom_key_bytes);

        manager.rotate_with_key(custom_key).unwrap();
        assert_eq!(manager.current_version(), 2);

        // Should be able to encrypt/decrypt with the custom key
        let (version, ciphertext) = manager.encrypt(b"test", None).unwrap();
        assert_eq!(version, 2);
        assert!(manager.decrypt(version, &ciphertext, None).is_ok());
    }

    #[test]
    fn test_multiple_rotations() {
        let mut manager = KeyRotationManager::<ChaCha20Poly1305>::new().unwrap();
        let mut plaintexts = vec![];
        let mut ciphertexts = vec![];

        // Encrypt with multiple versions
        for i in 0..5 {
            let plaintext = format!("Message {}", i);
            plaintexts.push(plaintext.clone());

            let (version, ciphertext) = manager.encrypt(plaintext.as_bytes(), None).unwrap();
            ciphertexts.push((version, ciphertext));

            if i < 4 {
                manager.rotate().unwrap();
            }
        }

        // All should decrypt correctly
        for (i, (version, ciphertext)) in ciphertexts.iter().enumerate() {
            let decrypted = manager.decrypt(*version, ciphertext, None).unwrap();
            assert_eq!(decrypted, plaintexts[i].as_bytes());
        }
    }
}
