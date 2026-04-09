//! Ed25519 digital signatures.
//!
//! Ed25519 is a fast, secure elliptic curve signature scheme.
//! It provides 128-bit security and is widely supported.

use crate::errors::{CrabError, CrabResult};
use ed25519_dalek::{
    Signature, Signer, SigningKey, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH,
    SIGNATURE_LENGTH,
};
use rand_core::OsRng;

/// Ed25519 signature (64 bytes).
///
/// With the `serde-support` feature, signatures can be serialized to/from JSON/TOML as base64 strings.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde-support", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde-support", serde(transparent))]
pub struct Ed25519Signature(
    #[cfg_attr(feature = "serde-support", serde(with = "serde_sig_bytes"))]
    pub  [u8; SIGNATURE_LENGTH],
);

#[cfg(feature = "serde-support")]
mod serde_sig_bytes {
    use super::SIGNATURE_LENGTH;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; SIGNATURE_LENGTH], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&crate::encoding::base64_encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; SIGNATURE_LENGTH], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = crate::encoding::base64_decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != SIGNATURE_LENGTH {
            return Err(serde::de::Error::custom(format!(
                "Expected {} bytes, got {}",
                SIGNATURE_LENGTH,
                bytes.len()
            )));
        }
        let mut arr = [0u8; SIGNATURE_LENGTH];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

impl Ed25519Signature {
    /// Creates a signature from bytes.
    pub fn from_bytes(bytes: &[u8]) -> CrabResult<Self> {
        if bytes.len() != SIGNATURE_LENGTH {
            return Err(CrabError::invalid_input(format!(
                "Ed25519 signature must be {} bytes, got {}",
                SIGNATURE_LENGTH,
                bytes.len()
            )));
        }

        let mut sig = [0u8; SIGNATURE_LENGTH];
        sig.copy_from_slice(bytes);
        Ok(Self(sig))
    }

    /// Returns signature as bytes.
    pub fn as_bytes(&self) -> &[u8; SIGNATURE_LENGTH] {
        &self.0
    }

    /// Encodes signature to base64.
    pub fn to_base64(&self) -> String {
        crate::encoding::base64_encode(&self.0)
    }

    /// Decodes signature from base64.
    pub fn from_base64(data: &str) -> CrabResult<Self> {
        let bytes = crate::encoding::base64_decode(data)?;
        Self::from_bytes(&bytes)
    }

    /// Encodes signature to hex.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Decodes signature from hex.
    pub fn from_hex(data: &str) -> CrabResult<Self> {
        let bytes = hex::decode(data)?;
        Self::from_bytes(&bytes)
    }
}

/// Ed25519 public key (32 bytes).
///
/// With the `serde-support` feature, public keys can be serialized to/from JSON/TOML as base64 strings.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde-support", derive(serde::Serialize, serde::Deserialize))]
pub struct Ed25519PublicKey(
    #[cfg_attr(feature = "serde-support", serde(with = "serde_pub_key"))] VerifyingKey,
);

#[cfg(feature = "serde-support")]
mod serde_pub_key {
    use super::{VerifyingKey, PUBLIC_KEY_LENGTH};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(key: &VerifyingKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&crate::encoding::base64_encode(key.as_bytes()))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<VerifyingKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = crate::encoding::base64_decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != PUBLIC_KEY_LENGTH {
            return Err(serde::de::Error::custom(format!(
                "Expected {} bytes, got {}",
                PUBLIC_KEY_LENGTH,
                bytes.len()
            )));
        }
        VerifyingKey::from_bytes(bytes[..PUBLIC_KEY_LENGTH].try_into().unwrap())
            .map_err(serde::de::Error::custom)
    }
}

impl Ed25519PublicKey {
    /// Creates a public key from bytes.
    pub fn from_bytes(bytes: &[u8]) -> CrabResult<Self> {
        if bytes.len() != PUBLIC_KEY_LENGTH {
            return Err(CrabError::invalid_input(format!(
                "Ed25519 public key must be {} bytes, got {}",
                PUBLIC_KEY_LENGTH,
                bytes.len()
            )));
        }

        let key = VerifyingKey::from_bytes(bytes.try_into().expect("length already checked"))
            .map_err(|e| CrabError::key_error(format!("Invalid Ed25519 public key: {}", e)))?;

        Ok(Self(key))
    }

    /// Returns public key as bytes.
    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
        self.0.as_bytes()
    }

    /// Verifies a signature on a message.
    ///
    /// # Returns
    /// `Ok(true)` if signature is valid, `Ok(false)` if invalid
    pub fn verify(&self, message: &[u8], signature: &Ed25519Signature) -> CrabResult<bool> {
        let sig = Signature::from_bytes(&signature.0);
        Ok(self.0.verify(message, &sig).is_ok())
    }

    /// Encodes public key to base64.
    pub fn to_base64(&self) -> String {
        crate::encoding::base64_encode(self.0.as_bytes())
    }

    /// Decodes public key from base64.
    pub fn from_base64(data: &str) -> CrabResult<Self> {
        let bytes = crate::encoding::base64_decode(data)?;
        Self::from_bytes(&bytes)
    }

    /// Encodes public key to hex.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0.as_bytes())
    }

    /// Decodes public key from hex.
    pub fn from_hex(data: &str) -> CrabResult<Self> {
        let bytes = hex::decode(data)?;
        Self::from_bytes(&bytes)
    }
}

/// Ed25519 keypair for signing and verification.
pub struct Ed25519KeyPair {
    signing_key: SigningKey,
}

impl Ed25519KeyPair {
    /// Generates a new random Ed25519 keypair.
    ///
    /// # Example
    /// ```
    /// use crabgraph::asym::Ed25519KeyPair;
    ///
    /// let keypair = Ed25519KeyPair::generate().unwrap();
    /// ```
    pub fn generate() -> CrabResult<Self> {
        let signing_key = SigningKey::generate(&mut OsRng);
        Ok(Self {
            signing_key,
        })
    }

    /// Creates a keypair from a 32-byte secret key.
    ///
    /// # Security Warning
    /// The secret key must be kept confidential and zeroized after use.
    pub fn from_secret_bytes(secret: &[u8]) -> CrabResult<Self> {
        if secret.len() != SECRET_KEY_LENGTH {
            return Err(CrabError::invalid_input(format!(
                "Ed25519 secret key must be {} bytes, got {}",
                SECRET_KEY_LENGTH,
                secret.len()
            )));
        }

        let signing_key =
            SigningKey::from_bytes(secret.try_into().expect("length already checked"));

        Ok(Self {
            signing_key,
        })
    }

    /// Returns the secret key bytes.
    ///
    /// # Security Warning
    /// Handle with care! Zeroize after use.
    pub fn secret_bytes(&self) -> &[u8; SECRET_KEY_LENGTH] {
        self.signing_key.as_bytes()
    }

    /// Returns the public key.
    pub fn public_key(&self) -> Ed25519PublicKey {
        Ed25519PublicKey(self.signing_key.verifying_key())
    }

    /// Signs a message and returns the signature.
    ///
    /// # Example
    /// ```
    /// use crabgraph::asym::Ed25519KeyPair;
    ///
    /// let keypair = Ed25519KeyPair::generate().unwrap();
    /// let message = b"Important message";
    /// let signature = keypair.sign(message);
    /// ```
    pub fn sign(&self, message: &[u8]) -> Ed25519Signature {
        let sig = self.signing_key.sign(message);
        Ed25519Signature(sig.to_bytes())
    }

    /// Signs a message and verifies it's correct (paranoid mode).
    ///
    /// This performs an extra verification step to ensure the signature is valid.
    pub fn sign_with_verification(&self, message: &[u8]) -> CrabResult<Ed25519Signature> {
        let signature = self.sign(message);

        // Verify immediately
        if !self.verify(message, &signature)? {
            return Err(CrabError::Internal("Signature verification failed after signing".into()));
        }

        Ok(signature)
    }

    /// Verifies a signature on a message using this keypair's public key.
    ///
    /// # Example
    /// ```
    /// use crabgraph::asym::Ed25519KeyPair;
    ///
    /// let keypair = Ed25519KeyPair::generate().unwrap();
    /// let message = b"Important message";
    /// let signature = keypair.sign(message);
    ///
    /// assert!(keypair.verify(message, &signature).unwrap());
    /// assert!(!keypair.verify(b"Wrong message", &signature).unwrap());
    /// ```
    pub fn verify(&self, message: &[u8], signature: &Ed25519Signature) -> CrabResult<bool> {
        self.public_key().verify(message, signature)
    }

    /// Exports the keypair to PKCS#8 DER format.
    ///
    /// This is the binary encoding format for private keys.
    ///
    /// # Example
    /// ```
    /// use crabgraph::asym::Ed25519KeyPair;
    ///
    /// let keypair = Ed25519KeyPair::generate().unwrap();
    /// let der = keypair.to_pkcs8_der().unwrap();
    /// let restored = Ed25519KeyPair::from_pkcs8_der(&der).unwrap();
    /// ```
    pub fn to_pkcs8_der(&self) -> CrabResult<Vec<u8>> {
        use ed25519_dalek::pkcs8::EncodePrivateKey;

        self.signing_key
            .to_pkcs8_der()
            .map(|doc| doc.as_bytes().to_vec())
            .map_err(|e| CrabError::key_error(format!("Failed to encode PKCS#8 DER: {}", e)))
    }

    /// Imports a keypair from PKCS#8 DER format.
    ///
    /// # Example
    /// ```
    /// use crabgraph::asym::Ed25519KeyPair;
    ///
    /// let keypair = Ed25519KeyPair::generate().unwrap();
    /// let der = keypair.to_pkcs8_der().unwrap();
    /// let restored = Ed25519KeyPair::from_pkcs8_der(&der).unwrap();
    ///
    /// let message = b"Test";
    /// let sig = keypair.sign(message);
    /// assert!(restored.verify(message, &sig).unwrap());
    /// ```
    pub fn from_pkcs8_der(der: &[u8]) -> CrabResult<Self> {
        use ed25519_dalek::pkcs8::DecodePrivateKey;

        let signing_key = SigningKey::from_pkcs8_der(der)
            .map_err(|e| CrabError::key_error(format!("Failed to decode PKCS#8 DER: {}", e)))?;

        Ok(Self {
            signing_key,
        })
    }

    /// Exports the keypair to PKCS#8 PEM format.
    ///
    /// This is the text-based encoding format commonly used in configuration files.
    ///
    /// # Example
    /// ```
    /// use crabgraph::asym::Ed25519KeyPair;
    ///
    /// let keypair = Ed25519KeyPair::generate().unwrap();
    /// let pem = keypair.to_pkcs8_pem().unwrap();
    /// assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));
    /// ```
    pub fn to_pkcs8_pem(&self) -> CrabResult<String> {
        use ed25519_dalek::pkcs8::EncodePrivateKey;

        self.signing_key
            .to_pkcs8_pem(Default::default())
            .map(|s| s.to_string())
            .map_err(|e| CrabError::key_error(format!("Failed to encode PKCS#8 PEM: {}", e)))
    }

    /// Imports a keypair from PKCS#8 PEM format.
    ///
    /// # Example
    /// ```
    /// use crabgraph::asym::Ed25519KeyPair;
    ///
    /// let keypair = Ed25519KeyPair::generate().unwrap();
    /// let pem = keypair.to_pkcs8_pem().unwrap();
    /// let restored = Ed25519KeyPair::from_pkcs8_pem(&pem).unwrap();
    ///
    /// let message = b"Test";
    /// let sig = keypair.sign(message);
    /// assert!(restored.verify(message, &sig).unwrap());
    /// ```
    pub fn from_pkcs8_pem(pem: &str) -> CrabResult<Self> {
        use ed25519_dalek::pkcs8::DecodePrivateKey;

        let signing_key = SigningKey::from_pkcs8_pem(pem)
            .map_err(|e| CrabError::key_error(format!("Failed to decode PKCS#8 PEM: {}", e)))?;

        Ok(Self {
            signing_key,
        })
    }
}

impl Ed25519PublicKey {
    /// Exports the public key to SPKI DER format (SubjectPublicKeyInfo).
    ///
    /// This is the standard binary encoding for public keys.
    ///
    /// # Example
    /// ```
    /// use crabgraph::asym::Ed25519KeyPair;
    ///
    /// let keypair = Ed25519KeyPair::generate().unwrap();
    /// let pubkey = keypair.public_key();
    /// let der = pubkey.to_public_key_der().unwrap();
    /// ```
    pub fn to_public_key_der(&self) -> CrabResult<Vec<u8>> {
        use ed25519_dalek::pkcs8::EncodePublicKey;

        self.0
            .to_public_key_der()
            .map(|doc| doc.as_bytes().to_vec())
            .map_err(|e| CrabError::key_error(format!("Failed to encode public key DER: {}", e)))
    }

    /// Imports a public key from SPKI DER format.
    ///
    /// # Example
    /// ```
    /// use crabgraph::asym::Ed25519KeyPair;
    ///
    /// let keypair = Ed25519KeyPair::generate().unwrap();
    /// let pubkey = keypair.public_key();
    /// let der = pubkey.to_public_key_der().unwrap();
    /// let restored = crabgraph::asym::Ed25519PublicKey::from_public_key_der(&der).unwrap();
    /// ```
    pub fn from_public_key_der(der: &[u8]) -> CrabResult<Self> {
        use ed25519_dalek::pkcs8::DecodePublicKey;

        let key = VerifyingKey::from_public_key_der(der)
            .map_err(|e| CrabError::key_error(format!("Failed to decode public key DER: {}", e)))?;

        Ok(Self(key))
    }

    /// Exports the public key to PEM format.
    ///
    /// # Example
    /// ```
    /// use crabgraph::asym::Ed25519KeyPair;
    ///
    /// let keypair = Ed25519KeyPair::generate().unwrap();
    /// let pubkey = keypair.public_key();
    /// let pem = pubkey.to_public_key_pem().unwrap();
    /// assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----"));
    /// ```
    pub fn to_public_key_pem(&self) -> CrabResult<String> {
        use ed25519_dalek::pkcs8::EncodePublicKey;

        self.0
            .to_public_key_pem(Default::default())
            .map_err(|e| CrabError::key_error(format!("Failed to encode public key PEM: {}", e)))
    }

    /// Imports a public key from PEM format.
    ///
    /// # Example
    /// ```
    /// use crabgraph::asym::Ed25519KeyPair;
    ///
    /// let keypair = Ed25519KeyPair::generate().unwrap();
    /// let pubkey = keypair.public_key();
    /// let pem = pubkey.to_public_key_pem().unwrap();
    /// let restored = crabgraph::asym::Ed25519PublicKey::from_public_key_pem(&pem).unwrap();
    /// ```
    pub fn from_public_key_pem(pem: &str) -> CrabResult<Self> {
        use ed25519_dalek::pkcs8::DecodePublicKey;

        let key = VerifyingKey::from_public_key_pem(pem)
            .map_err(|e| CrabError::key_error(format!("Failed to decode public key PEM: {}", e)))?;

        Ok(Self(key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_generate_and_sign() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let message = b"Test message";
        let signature = keypair.sign(message);

        assert!(keypair.verify(message, &signature).unwrap());
    }

    #[test]
    fn test_ed25519_verify_wrong_message() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let message = b"Test message";
        let signature = keypair.sign(message);

        assert!(!keypair.verify(b"Wrong message", &signature).unwrap());
    }

    #[test]
    fn test_ed25519_public_key_verify() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let public_key = keypair.public_key();
        let message = b"Test message";
        let signature = keypair.sign(message);

        assert!(public_key.verify(message, &signature).unwrap());
        assert!(!public_key.verify(b"Wrong", &signature).unwrap());
    }

    #[test]
    fn test_ed25519_from_secret_bytes() {
        let keypair1 = Ed25519KeyPair::generate().unwrap();
        let secret = keypair1.secret_bytes();

        let keypair2 = Ed25519KeyPair::from_secret_bytes(secret).unwrap();

        // Same secret should produce same public key
        assert_eq!(keypair1.public_key().as_bytes(), keypair2.public_key().as_bytes());
    }

    #[test]
    fn test_ed25519_signature_serialization() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let message = b"Test";
        let signature = keypair.sign(message);

        // Base64
        let b64 = signature.to_base64();
        let recovered = Ed25519Signature::from_base64(&b64).unwrap();
        assert_eq!(signature, recovered);

        // Hex
        let hex = signature.to_hex();
        let recovered = Ed25519Signature::from_hex(&hex).unwrap();
        assert_eq!(signature, recovered);
    }

    #[test]
    fn test_ed25519_public_key_serialization() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let public_key = keypair.public_key();

        // Base64
        let b64 = public_key.to_base64();
        let recovered = Ed25519PublicKey::from_base64(&b64).unwrap();
        assert_eq!(public_key.as_bytes(), recovered.as_bytes());

        // Hex
        let hex = public_key.to_hex();
        let recovered = Ed25519PublicKey::from_hex(&hex).unwrap();
        assert_eq!(public_key.as_bytes(), recovered.as_bytes());
    }

    #[test]
    fn test_ed25519_sign_with_verification() {
        let keypair = Ed25519KeyPair::generate().unwrap();
        let message = b"Test message";
        let signature = keypair.sign_with_verification(message).unwrap();

        assert!(keypair.verify(message, &signature).unwrap());
    }
}
