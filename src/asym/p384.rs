//! P-384 (secp384r1) elliptic curve cryptography.
//!
//! This module provides ECDH key exchange and ECDSA signatures using the
//! NIST P-384 curve (also known as secp384r1).
//!
//! P-384 provides higher security than P-256 and is required for some
//! compliance scenarios (e.g., certain government standards).
//!
//! **Requires**: `tls` feature flag
//!
//! # Example: Key Exchange (ECDH)
//! ```ignore
//! use crabgraph::asym::p384::{P384KeyPair, P384PublicKey};
//!
//! // Alice and Bob generate keypairs
//! let alice = P384KeyPair::generate()?;
//! let bob = P384KeyPair::generate()?;
//!
//! // Exchange public keys and compute shared secret
//! let alice_shared = alice.diffie_hellman(&bob.public_key())?;
//! let bob_shared = bob.diffie_hellman(&alice.public_key())?;
//!
//! assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
//! # Ok::<(), crabgraph::CrabError>(())
//! ```
//!
//! # Example: Digital Signatures (ECDSA)
//! ```ignore
//! use crabgraph::asym::p384::P384SigningKey;
//!
//! let signing_key = P384SigningKey::generate()?;
//! let message = b"Hello, P-384!";
//!
//! let signature = signing_key.sign(message)?;
//! assert!(signing_key.verifying_key().verify(message, &signature)?);
//! # Ok::<(), crabgraph::CrabError>(())
//! ```

use crate::errors::{CrabError, CrabResult};
use crate::secrets::SecretVec;
use p384::{
    ecdsa::{
        signature::{Signer, Verifier},
        Signature, SigningKey, VerifyingKey,
    },
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
    EncodedPoint, PublicKey, SecretKey,
};
use rand_core::OsRng;

/// P-384 scalar size in bytes (48 bytes for private key).
const P384_SCALAR_SIZE: usize = 48;
/// P-384 signature size (96 bytes: 48-byte r + 48-byte s).
const P384_SIGNATURE_SIZE: usize = 96;

// ============================================================================
// Shared Secret (ECDH output)
// ============================================================================

/// P-384 shared secret from ECDH key exchange.
///
/// This is the raw shared secret. Use `derive_key()` to convert it to
/// an encryption key via HKDF.
#[derive(Clone)]
pub struct P384SharedSecret(SecretVec);

impl P384SharedSecret {
    /// Creates a shared secret from raw bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> CrabResult<Self> {
        if bytes.len() != P384_SCALAR_SIZE {
            return Err(CrabError::invalid_input(format!(
                "P-384 shared secret must be {} bytes, got {}",
                P384_SCALAR_SIZE,
                bytes.len()
            )));
        }
        Ok(Self(SecretVec::new(bytes)))
    }

    /// Returns the shared secret as bytes.
    ///
    /// # Security Warning
    /// Do not use this directly as an encryption key! Use a KDF (HKDF) first.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Derives an encryption key from the shared secret using HKDF.
    ///
    /// This is the recommended way to convert a shared secret into a key.
    ///
    /// # Example
    /// ```ignore
    /// use crabgraph::asym::p384::P384KeyPair;
    ///
    /// let alice = P384KeyPair::generate()?;
    /// let bob = P384KeyPair::generate()?;
    ///
    /// let shared = alice.diffie_hellman(&bob.public_key())?;
    /// let key = shared.derive_key(b"my_app_v1", 32)?;
    /// assert_eq!(key.len(), 32);
    /// # Ok::<(), crabgraph::CrabError>(())
    /// ```
    pub fn derive_key(&self, info: &[u8], key_len: usize) -> CrabResult<SecretVec> {
        crate::kdf::hkdf_extract_expand(&[], self.as_bytes(), info, key_len)
    }
}

impl std::fmt::Debug for P384SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "P384SharedSecret([REDACTED])")
    }
}

// ============================================================================
// Public Key (ECDH)
// ============================================================================

/// P-384 public key for ECDH key exchange.
#[derive(Clone, Debug)]
pub struct P384PublicKey(PublicKey);

impl P384PublicKey {
    /// Creates a public key from SEC1-encoded bytes (uncompressed or compressed).
    pub fn from_sec1_bytes(bytes: &[u8]) -> CrabResult<Self> {
        let encoded = EncodedPoint::from_bytes(bytes)
            .map_err(|e| CrabError::key_error(format!("Invalid SEC1 encoding: {}", e)))?;
        let public_key = PublicKey::from_encoded_point(&encoded);
        if public_key.is_none().into() {
            return Err(CrabError::key_error("Invalid P-384 public key point"));
        }
        Ok(Self(public_key.unwrap()))
    }

    /// Returns the public key as SEC1-encoded bytes (uncompressed format, 97 bytes).
    pub fn to_sec1_bytes(&self) -> Vec<u8> {
        self.0.to_encoded_point(false).as_bytes().to_vec()
    }

    /// Returns the public key as SEC1-encoded bytes (compressed format, 49 bytes).
    pub fn to_sec1_compressed(&self) -> Vec<u8> {
        self.0.to_encoded_point(true).as_bytes().to_vec()
    }

    /// Encodes public key to base64 (uncompressed SEC1 format).
    pub fn to_base64(&self) -> String {
        crate::encoding::base64_encode(&self.to_sec1_bytes())
    }

    /// Decodes public key from base64.
    pub fn from_base64(data: &str) -> CrabResult<Self> {
        let bytes = crate::encoding::base64_decode(data)?;
        Self::from_sec1_bytes(&bytes)
    }

    /// Encodes public key to hex (uncompressed SEC1 format).
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_sec1_bytes())
    }

    /// Decodes public key from hex.
    pub fn from_hex(data: &str) -> CrabResult<Self> {
        let bytes = hex::decode(data)?;
        Self::from_sec1_bytes(&bytes)
    }

    /// Returns the inner p384 PublicKey.
    pub(crate) fn inner(&self) -> &PublicKey {
        &self.0
    }
}

impl PartialEq for P384PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.to_sec1_bytes() == other.to_sec1_bytes()
    }
}

// ============================================================================
// Key Pair (ECDH)
// ============================================================================

/// P-384 keypair for ECDH key exchange.
///
/// This is a long-term static key that can be stored and reused.
pub struct P384KeyPair {
    secret: SecretKey,
}

impl P384KeyPair {
    /// Generates a new random P-384 keypair.
    ///
    /// # Example
    /// ```ignore
    /// use crabgraph::asym::p384::P384KeyPair;
    ///
    /// let keypair = P384KeyPair::generate()?;
    /// # Ok::<(), crabgraph::CrabError>(())
    /// ```
    pub fn generate() -> CrabResult<Self> {
        let secret = SecretKey::random(&mut OsRng);
        Ok(Self {
            secret,
        })
    }

    /// Creates a keypair from raw secret key bytes (48 bytes).
    pub fn from_secret_bytes(bytes: &[u8]) -> CrabResult<Self> {
        if bytes.len() != P384_SCALAR_SIZE {
            return Err(CrabError::invalid_input(format!(
                "P-384 secret key must be {} bytes, got {}",
                P384_SCALAR_SIZE,
                bytes.len()
            )));
        }
        let secret = SecretKey::from_slice(bytes)
            .map_err(|e| CrabError::key_error(format!("Invalid P-384 secret key: {}", e)))?;
        Ok(Self {
            secret,
        })
    }

    /// Returns the secret key bytes.
    ///
    /// # Security Warning
    /// Handle with care! Zeroize after use.
    pub fn secret_bytes(&self) -> [u8; P384_SCALAR_SIZE] {
        self.secret.to_bytes().into()
    }

    /// Returns the public key.
    pub fn public_key(&self) -> P384PublicKey {
        P384PublicKey(self.secret.public_key())
    }

    /// Performs ECDH key exchange with another party's public key.
    ///
    /// # Returns
    /// A shared secret that both parties can compute.
    ///
    /// # Security Notes
    /// - The shared secret should be passed through a KDF before use
    /// - Use `P384SharedSecret::derive_key()` for this
    ///
    /// # Example
    /// ```ignore
    /// use crabgraph::asym::p384::P384KeyPair;
    ///
    /// let alice = P384KeyPair::generate()?;
    /// let bob = P384KeyPair::generate()?;
    ///
    /// let alice_shared = alice.diffie_hellman(&bob.public_key())?;
    /// let bob_shared = bob.diffie_hellman(&alice.public_key())?;
    ///
    /// assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    /// # Ok::<(), crabgraph::CrabError>(())
    /// ```
    pub fn diffie_hellman(&self, their_public: &P384PublicKey) -> CrabResult<P384SharedSecret> {
        use p384::ecdh::diffie_hellman;

        let shared =
            diffie_hellman(self.secret.to_nonzero_scalar(), their_public.inner().as_affine());
        P384SharedSecret::from_bytes(shared.raw_secret_bytes().to_vec())
    }
}

impl std::fmt::Debug for P384KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "P384KeyPair {{ public_key: {:?} }}", self.public_key())
    }
}

// ============================================================================
// ECDSA Signature
// ============================================================================

/// P-384 ECDSA signature (96 bytes: 48-byte r + 48-byte s).
#[derive(Clone, Debug, PartialEq)]
pub struct P384Signature(Signature);

impl P384Signature {
    /// Creates a signature from raw bytes (96 bytes).
    pub fn from_bytes(bytes: &[u8]) -> CrabResult<Self> {
        if bytes.len() != P384_SIGNATURE_SIZE {
            return Err(CrabError::invalid_input(format!(
                "P-384 signature must be {} bytes, got {}",
                P384_SIGNATURE_SIZE,
                bytes.len()
            )));
        }
        let sig = Signature::from_slice(bytes)
            .map_err(|e| CrabError::crypto_error(format!("Invalid P-384 signature: {}", e)))?;
        Ok(Self(sig))
    }

    /// Creates a signature from DER-encoded bytes.
    pub fn from_der(bytes: &[u8]) -> CrabResult<Self> {
        let sig = Signature::from_der(bytes)
            .map_err(|e| CrabError::crypto_error(format!("Invalid DER signature: {}", e)))?;
        Ok(Self(sig))
    }

    /// Returns the signature as raw bytes (96 bytes).
    pub fn as_bytes(&self) -> Vec<u8> {
        self.0.to_bytes().to_vec()
    }

    /// Returns the signature in DER encoding.
    pub fn to_der(&self) -> Vec<u8> {
        self.0.to_der().as_bytes().to_vec()
    }

    /// Encodes signature to base64.
    pub fn to_base64(&self) -> String {
        crate::encoding::base64_encode(&self.as_bytes())
    }

    /// Decodes signature from base64.
    pub fn from_base64(data: &str) -> CrabResult<Self> {
        let bytes = crate::encoding::base64_decode(data)?;
        Self::from_bytes(&bytes)
    }

    /// Encodes signature to hex.
    pub fn to_hex(&self) -> String {
        hex::encode(self.as_bytes())
    }

    /// Decodes signature from hex.
    pub fn from_hex(data: &str) -> CrabResult<Self> {
        let bytes = hex::decode(data)?;
        Self::from_bytes(&bytes)
    }

    /// Returns the inner signature.
    pub(crate) fn inner(&self) -> &Signature {
        &self.0
    }
}

// ============================================================================
// ECDSA Verifying Key (public key for signature verification)
// ============================================================================

/// P-384 ECDSA verifying key (public key for signature verification).
#[derive(Clone, Debug)]
pub struct P384VerifyingKey(VerifyingKey);

impl P384VerifyingKey {
    /// Creates a verifying key from SEC1-encoded bytes.
    pub fn from_sec1_bytes(bytes: &[u8]) -> CrabResult<Self> {
        let key = VerifyingKey::from_sec1_bytes(bytes)
            .map_err(|e| CrabError::key_error(format!("Invalid P-384 verifying key: {}", e)))?;
        Ok(Self(key))
    }

    /// Returns the verifying key as SEC1-encoded bytes (uncompressed, 97 bytes).
    pub fn to_sec1_bytes(&self) -> Vec<u8> {
        self.0.to_encoded_point(false).as_bytes().to_vec()
    }

    /// Returns the verifying key as SEC1-encoded bytes (compressed, 49 bytes).
    pub fn to_sec1_compressed(&self) -> Vec<u8> {
        self.0.to_encoded_point(true).as_bytes().to_vec()
    }

    /// Verifies a signature against a message.
    ///
    /// # Returns
    /// `Ok(true)` if verification succeeds, `Ok(false)` or an error otherwise.
    ///
    /// # Example
    /// ```ignore
    /// use crabgraph::asym::p384::P384SigningKey;
    ///
    /// let signing_key = P384SigningKey::generate()?;
    /// let message = b"Hello!";
    /// let signature = signing_key.sign(message)?;
    ///
    /// assert!(signing_key.verifying_key().verify(message, &signature)?);
    /// # Ok::<(), crabgraph::CrabError>(())
    /// ```
    pub fn verify(&self, message: &[u8], signature: &P384Signature) -> CrabResult<bool> {
        match self.0.verify(message, signature.inner()) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Encodes verifying key to base64.
    pub fn to_base64(&self) -> String {
        crate::encoding::base64_encode(&self.to_sec1_bytes())
    }

    /// Decodes verifying key from base64.
    pub fn from_base64(data: &str) -> CrabResult<Self> {
        let bytes = crate::encoding::base64_decode(data)?;
        Self::from_sec1_bytes(&bytes)
    }
}

impl PartialEq for P384VerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.to_sec1_bytes() == other.to_sec1_bytes()
    }
}

// ============================================================================
// ECDSA Signing Key
// ============================================================================

/// P-384 ECDSA signing key (private key for creating signatures).
pub struct P384SigningKey(SigningKey);

impl P384SigningKey {
    /// Generates a new random P-384 ECDSA signing key.
    ///
    /// # Example
    /// ```ignore
    /// use crabgraph::asym::p384::P384SigningKey;
    ///
    /// let signing_key = P384SigningKey::generate()?;
    /// # Ok::<(), crabgraph::CrabError>(())
    /// ```
    pub fn generate() -> CrabResult<Self> {
        let key = SigningKey::random(&mut OsRng);
        Ok(Self(key))
    }

    /// Creates a signing key from raw secret bytes (48 bytes).
    pub fn from_bytes(bytes: &[u8]) -> CrabResult<Self> {
        if bytes.len() != P384_SCALAR_SIZE {
            return Err(CrabError::invalid_input(format!(
                "P-384 signing key must be {} bytes, got {}",
                P384_SCALAR_SIZE,
                bytes.len()
            )));
        }
        let key = SigningKey::from_slice(bytes)
            .map_err(|e| CrabError::key_error(format!("Invalid P-384 signing key: {}", e)))?;
        Ok(Self(key))
    }

    /// Returns the signing key as raw bytes.
    ///
    /// # Security Warning
    /// Handle with care! Zeroize after use.
    pub fn to_bytes(&self) -> [u8; P384_SCALAR_SIZE] {
        self.0.to_bytes().into()
    }

    /// Returns the corresponding verifying key.
    pub fn verifying_key(&self) -> P384VerifyingKey {
        P384VerifyingKey(*self.0.verifying_key())
    }

    /// Signs a message and returns the signature.
    ///
    /// # Example
    /// ```ignore
    /// use crabgraph::asym::p384::P384SigningKey;
    ///
    /// let signing_key = P384SigningKey::generate()?;
    /// let message = b"Hello, P-384!";
    /// let signature = signing_key.sign(message)?;
    /// # Ok::<(), crabgraph::CrabError>(())
    /// ```
    pub fn sign(&self, message: &[u8]) -> CrabResult<P384Signature> {
        let sig: Signature = self.0.sign(message);
        Ok(P384Signature(sig))
    }
}

impl std::fmt::Debug for P384SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "P384SigningKey([REDACTED])")
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p384_keypair_generation() {
        let keypair = P384KeyPair::generate().unwrap();
        let public_key = keypair.public_key();

        // Public key should be 97 bytes uncompressed (04 prefix + 48 x + 48 y)
        assert_eq!(public_key.to_sec1_bytes().len(), 97);
        assert_eq!(public_key.to_sec1_bytes()[0], 0x04);

        // Compressed should be 49 bytes
        assert_eq!(public_key.to_sec1_compressed().len(), 49);
    }

    #[test]
    fn test_p384_ecdh_key_exchange() {
        let alice = P384KeyPair::generate().unwrap();
        let bob = P384KeyPair::generate().unwrap();

        let alice_shared = alice.diffie_hellman(&bob.public_key()).unwrap();
        let bob_shared = bob.diffie_hellman(&alice.public_key()).unwrap();

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
        assert_eq!(alice_shared.as_bytes().len(), 48);
    }

    #[test]
    fn test_p384_shared_secret_key_derivation() {
        let alice = P384KeyPair::generate().unwrap();
        let bob = P384KeyPair::generate().unwrap();

        let shared = alice.diffie_hellman(&bob.public_key()).unwrap();
        let key = shared.derive_key(b"test_app", 32).unwrap();

        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_p384_public_key_roundtrip() {
        let keypair = P384KeyPair::generate().unwrap();
        let public_key = keypair.public_key();

        // Uncompressed roundtrip
        let bytes = public_key.to_sec1_bytes();
        let restored = P384PublicKey::from_sec1_bytes(&bytes).unwrap();
        assert_eq!(public_key, restored);

        // Compressed roundtrip
        let compressed = public_key.to_sec1_compressed();
        let restored_compressed = P384PublicKey::from_sec1_bytes(&compressed).unwrap();
        assert_eq!(public_key, restored_compressed);
    }

    #[test]
    fn test_p384_keypair_from_secret_bytes() {
        let original = P384KeyPair::generate().unwrap();
        let secret_bytes = original.secret_bytes();

        let restored = P384KeyPair::from_secret_bytes(&secret_bytes).unwrap();
        assert_eq!(original.public_key(), restored.public_key());
    }

    #[test]
    fn test_p384_ecdsa_sign_verify() {
        let signing_key = P384SigningKey::generate().unwrap();
        let message = b"Hello, P-384 ECDSA!";

        let signature = signing_key.sign(message).unwrap();
        let verifying_key = signing_key.verifying_key();

        assert!(verifying_key.verify(message, &signature).unwrap());
    }

    #[test]
    fn test_p384_ecdsa_wrong_message_fails() {
        let signing_key = P384SigningKey::generate().unwrap();
        let message = b"Original message";
        let wrong_message = b"Wrong message";

        let signature = signing_key.sign(message).unwrap();
        let verifying_key = signing_key.verifying_key();

        assert!(!verifying_key.verify(wrong_message, &signature).unwrap());
    }

    #[test]
    fn test_p384_signature_roundtrip() {
        let signing_key = P384SigningKey::generate().unwrap();
        let message = b"Test message";
        let signature = signing_key.sign(message).unwrap();

        // Raw bytes roundtrip
        let bytes = signature.as_bytes();
        let restored = P384Signature::from_bytes(&bytes).unwrap();
        assert_eq!(signature, restored);

        // DER roundtrip
        let der = signature.to_der();
        let restored_der = P384Signature::from_der(&der).unwrap();
        assert_eq!(signature.as_bytes(), restored_der.as_bytes());
    }

    #[test]
    fn test_p384_signing_key_from_bytes() {
        let original = P384SigningKey::generate().unwrap();
        let bytes = original.to_bytes();

        let restored = P384SigningKey::from_bytes(&bytes).unwrap();

        // Verify both keys produce the same verifying key
        assert_eq!(
            original.verifying_key().to_sec1_bytes(),
            restored.verifying_key().to_sec1_bytes()
        );
    }

    #[test]
    fn test_p384_public_key_encoding() {
        let keypair = P384KeyPair::generate().unwrap();
        let public_key = keypair.public_key();

        // Base64 roundtrip
        let b64 = public_key.to_base64();
        let restored = P384PublicKey::from_base64(&b64).unwrap();
        assert_eq!(public_key, restored);

        // Hex roundtrip
        let hex_str = public_key.to_hex();
        let restored_hex = P384PublicKey::from_hex(&hex_str).unwrap();
        assert_eq!(public_key, restored_hex);
    }
}
