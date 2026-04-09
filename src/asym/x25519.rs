//! X25519 Diffie-Hellman key exchange.
//!
//! X25519 is a fast, secure key exchange protocol built on Curve25519.
//! It's used to establish shared secrets for encryption.

use crate::errors::{CrabError, CrabResult};
use crate::secrets::SecretVec;
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

const X25519_KEY_SIZE: usize = 32;

/// X25519 shared secret (32 bytes).
///
/// This is the output of the key exchange and should be used with a KDF
/// before using as an encryption key.
#[derive(Clone)]
pub struct X25519SharedSecret(SecretVec);

impl X25519SharedSecret {
    /// Creates a shared secret from bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> CrabResult<Self> {
        if bytes.len() != X25519_KEY_SIZE {
            return Err(CrabError::invalid_input(format!(
                "X25519 shared secret must be {} bytes, got {}",
                X25519_KEY_SIZE,
                bytes.len()
            )));
        }
        Ok(Self(SecretVec::new(bytes)))
    }

    /// Returns shared secret as bytes.
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
    /// ```
    /// use crabgraph::asym::X25519KeyPair;
    ///
    /// let alice = X25519KeyPair::generate().unwrap();
    /// let bob = X25519KeyPair::generate().unwrap();
    ///
    /// let shared = alice.diffie_hellman(&bob.public_key()).unwrap();
    /// let key = shared.derive_key(b"my_app_v1", 32).unwrap();
    /// assert_eq!(key.len(), 32);
    /// ```
    pub fn derive_key(&self, info: &[u8], key_len: usize) -> CrabResult<SecretVec> {
        crate::kdf::hkdf_extract_expand(&[], self.as_bytes(), info, key_len)
    }
}

impl std::fmt::Debug for X25519SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "X25519SharedSecret([REDACTED])")
    }
}

/// X25519 public key (32 bytes).
#[derive(Clone, Debug, PartialEq)]
pub struct X25519PublicKey(PublicKey);

impl X25519PublicKey {
    /// Creates a public key from bytes.
    pub fn from_bytes(bytes: &[u8]) -> CrabResult<Self> {
        if bytes.len() != X25519_KEY_SIZE {
            return Err(CrabError::invalid_input(format!(
                "X25519 public key must be {} bytes, got {}",
                X25519_KEY_SIZE,
                bytes.len()
            )));
        }

        let mut key_bytes = [0u8; X25519_KEY_SIZE];
        key_bytes.copy_from_slice(bytes);
        Ok(Self(PublicKey::from(key_bytes)))
    }

    /// Returns public key as bytes.
    pub fn as_bytes(&self) -> &[u8; X25519_KEY_SIZE] {
        self.0.as_bytes()
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

/// X25519 keypair for Diffie-Hellman key exchange.
pub struct X25519KeyPair {
    secret: StaticSecret,
}

impl X25519KeyPair {
    /// Generates a new random X25519 keypair.
    ///
    /// # Example
    /// ```
    /// use crabgraph::asym::X25519KeyPair;
    ///
    /// let keypair = X25519KeyPair::generate().unwrap();
    /// ```
    pub fn generate() -> CrabResult<Self> {
        let secret = StaticSecret::random_from_rng(OsRng);
        Ok(Self {
            secret,
        })
    }

    /// Creates a keypair from a 32-byte secret key.
    ///
    /// # Security Warning
    /// The secret key must be kept confidential and zeroized after use.
    pub fn from_secret_bytes(secret: &[u8]) -> CrabResult<Self> {
        if secret.len() != X25519_KEY_SIZE {
            return Err(CrabError::invalid_input(format!(
                "X25519 secret key must be {} bytes, got {}",
                X25519_KEY_SIZE,
                secret.len()
            )));
        }

        let mut key_bytes = [0u8; X25519_KEY_SIZE];
        key_bytes.copy_from_slice(secret);
        let secret = StaticSecret::from(key_bytes);

        Ok(Self {
            secret,
        })
    }

    /// Returns the secret key bytes.
    ///
    /// # Security Warning
    /// Handle with care! Zeroize after use.
    pub fn secret_bytes(&self) -> &[u8; X25519_KEY_SIZE] {
        self.secret.as_bytes()
    }

    /// Returns the public key.
    pub fn public_key(&self) -> X25519PublicKey {
        X25519PublicKey(PublicKey::from(&self.secret))
    }

    /// Performs Diffie-Hellman key exchange with another party's public key.
    ///
    /// # Returns
    /// A shared secret that both parties can compute.
    ///
    /// # Security Notes
    /// - The shared secret should be passed through a KDF before use
    /// - Use `X25519SharedSecret::derive_key()` for this
    ///
    /// # Example
    /// ```
    /// use crabgraph::asym::X25519KeyPair;
    ///
    /// // Alice and Bob generate keypairs
    /// let alice = X25519KeyPair::generate().unwrap();
    /// let bob = X25519KeyPair::generate().unwrap();
    ///
    /// // Exchange public keys and compute shared secret
    /// let alice_shared = alice.diffie_hellman(&bob.public_key()).unwrap();
    /// let bob_shared = bob.diffie_hellman(&alice.public_key()).unwrap();
    ///
    /// // Both should have the same shared secret
    /// assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    /// ```
    pub fn diffie_hellman(&self, their_public: &X25519PublicKey) -> CrabResult<X25519SharedSecret> {
        let shared = self.secret.diffie_hellman(&their_public.0);
        Ok(X25519SharedSecret(SecretVec::new(shared.as_bytes().to_vec())))
    }

    /// Exports the keypair to PKCS#8 DER format.
    ///
    /// This is the binary encoding format for private keys.
    ///
    /// # Example
    /// ```
    /// use crabgraph::asym::X25519KeyPair;
    ///
    /// let keypair = X25519KeyPair::generate().unwrap();
    /// let der = keypair.to_pkcs8_der().unwrap();
    /// let restored = X25519KeyPair::from_pkcs8_der(&der).unwrap();
    /// ```
    pub fn to_pkcs8_der(&self) -> CrabResult<Vec<u8>> {
        use pkcs8::{der::Encode, ObjectIdentifier};

        // X25519 OID: 1.3.101.110
        const X25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.110");

        let private_key_info = pkcs8::PrivateKeyInfo::new(
            pkcs8::AlgorithmIdentifierRef {
                oid: X25519_OID,
                parameters: None,
            },
            self.secret.as_bytes(),
        );

        private_key_info
            .to_der()
            .map_err(|e| CrabError::key_error(format!("Failed to encode PKCS#8 DER: {}", e)))
    }

    /// Imports a keypair from PKCS#8 DER format.
    ///
    /// # Example
    /// ```
    /// use crabgraph::asym::X25519KeyPair;
    ///
    /// let keypair = X25519KeyPair::generate().unwrap();
    /// let der = keypair.to_pkcs8_der().unwrap();
    /// let restored = X25519KeyPair::from_pkcs8_der(&der).unwrap();
    ///
    /// let bob = X25519KeyPair::generate().unwrap();
    /// let shared1 = keypair.diffie_hellman(&bob.public_key()).unwrap();
    /// let shared2 = restored.diffie_hellman(&bob.public_key()).unwrap();
    /// assert_eq!(shared1.as_bytes(), shared2.as_bytes());
    /// ```
    pub fn from_pkcs8_der(der: &[u8]) -> CrabResult<Self> {
        use pkcs8::{der::Decode, ObjectIdentifier};

        const X25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.110");

        let private_key_info = pkcs8::PrivateKeyInfo::from_der(der)
            .map_err(|e| CrabError::key_error(format!("Failed to decode PKCS#8 DER: {}", e)))?;

        if private_key_info.algorithm.oid != X25519_OID {
            return Err(CrabError::key_error(format!(
                "Expected X25519 OID ({}), found {}",
                X25519_OID, private_key_info.algorithm.oid
            )));
        }

        if private_key_info.private_key.len() != X25519_KEY_SIZE {
            return Err(CrabError::key_error(format!(
                "Expected {} bytes of private key data, found {}",
                X25519_KEY_SIZE,
                private_key_info.private_key.len()
            )));
        }

        Self::from_secret_bytes(private_key_info.private_key)
    }

    /// Exports the keypair to PKCS#8 PEM format.
    ///
    /// This is the text-based encoding format commonly used in configuration files.
    ///
    /// # Example
    /// ```
    /// use crabgraph::asym::X25519KeyPair;
    ///
    /// let keypair = X25519KeyPair::generate().unwrap();
    /// let pem = keypair.to_pkcs8_pem().unwrap();
    /// assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));
    /// ```
    pub fn to_pkcs8_pem(&self) -> CrabResult<String> {
        use pkcs8::der::{Decode, EncodePem};

        let der = self.to_pkcs8_der()?;
        let private_key_info = pkcs8::PrivateKeyInfo::from_der(&der)
            .map_err(|e| CrabError::key_error(format!("Failed to parse DER: {}", e)))?;

        let pem = private_key_info
            .to_pem(Default::default())
            .map_err(|e| CrabError::key_error(format!("Failed to encode PKCS#8 PEM: {}", e)))?;

        Ok(pem.to_string())
    }

    /// Imports a keypair from PKCS#8 PEM format.
    ///
    /// # Example
    /// ```
    /// use crabgraph::asym::X25519KeyPair;
    ///
    /// let keypair = X25519KeyPair::generate().unwrap();
    /// let pem = keypair.to_pkcs8_pem().unwrap();
    /// let restored = X25519KeyPair::from_pkcs8_pem(&pem).unwrap();
    ///
    /// let bob = X25519KeyPair::generate().unwrap();
    /// let shared1 = keypair.diffie_hellman(&bob.public_key()).unwrap();
    /// let shared2 = restored.diffie_hellman(&bob.public_key()).unwrap();
    /// assert_eq!(shared1.as_bytes(), shared2.as_bytes());
    /// ```
    pub fn from_pkcs8_pem(pem: &str) -> CrabResult<Self> {
        let (_, doc) = pkcs8::Document::from_pem(pem)
            .map_err(|e| CrabError::key_error(format!("Failed to decode PKCS#8 PEM: {}", e)))?;

        Self::from_pkcs8_der(doc.as_bytes())
    }
}

impl X25519PublicKey {
    /// Exports the public key to SPKI DER format (SubjectPublicKeyInfo).
    ///
    /// This is the standard binary encoding for public keys.
    ///
    /// # Example
    /// ```
    /// use crabgraph::asym::X25519KeyPair;
    ///
    /// let keypair = X25519KeyPair::generate().unwrap();
    /// let pubkey = keypair.public_key();
    /// let der = pubkey.to_public_key_der().unwrap();
    /// ```
    pub fn to_public_key_der(&self) -> CrabResult<Vec<u8>> {
        use pkcs8::der::Encode;

        // X25519 OID: 1.3.101.110
        const X25519_OID: pkcs8::ObjectIdentifier =
            pkcs8::ObjectIdentifier::new_unwrap("1.3.101.110");

        // Create bit string from public key bytes
        let bit_string = pkcs8::der::asn1::BitStringRef::from_bytes(self.0.as_bytes())
            .map_err(|e| CrabError::key_error(format!("Failed to create bit string: {}", e)))?;

        // Create SubjectPublicKeyInfo using owned type with constructor
        let spki = pkcs8::SubjectPublicKeyInfo {
            algorithm: pkcs8::AlgorithmIdentifierRef {
                oid: X25519_OID,
                parameters: None,
            },
            subject_public_key: bit_string,
        };

        // Encode to DER
        spki.to_der()
            .map_err(|e| CrabError::key_error(format!("Failed to encode public key DER: {}", e)))
    }

    /// Imports a public key from SPKI DER format.
    ///
    /// # Example
    /// ```
    /// use crabgraph::asym::X25519KeyPair;
    ///
    /// let keypair = X25519KeyPair::generate().unwrap();
    /// let pubkey = keypair.public_key();
    /// let der = pubkey.to_public_key_der().unwrap();
    /// let restored = crabgraph::asym::X25519PublicKey::from_public_key_der(&der).unwrap();
    /// ```
    pub fn from_public_key_der(der: &[u8]) -> CrabResult<Self> {
        use pkcs8::der::Decode;

        const X25519_OID: pkcs8::ObjectIdentifier =
            pkcs8::ObjectIdentifier::new_unwrap("1.3.101.110");

        // Parse DER using Ref type for zero-copy parsing
        let spki = pkcs8::SubjectPublicKeyInfoRef::from_der(der)
            .map_err(|e| CrabError::key_error(format!("Failed to decode public key DER: {}", e)))?;

        // Verify algorithm OID
        if spki.algorithm.oid != X25519_OID {
            return Err(CrabError::key_error(format!(
                "Expected X25519 OID ({}), found {}",
                X25519_OID, spki.algorithm.oid
            )));
        }

        // Extract public key bytes from bit string
        let key_bytes = spki.subject_public_key.as_bytes().ok_or_else(|| {
            CrabError::key_error("Failed to extract public key bytes".to_string())
        })?;

        if key_bytes.len() != X25519_KEY_SIZE {
            return Err(CrabError::key_error(format!(
                "Expected {} bytes of public key data, found {}",
                X25519_KEY_SIZE,
                key_bytes.len()
            )));
        }

        Self::from_bytes(key_bytes)
    }

    /// Exports the public key to PEM format.
    ///
    /// # Example
    /// ```
    /// use crabgraph::asym::X25519KeyPair;
    ///
    /// let keypair = X25519KeyPair::generate().unwrap();
    /// let pubkey = keypair.public_key();
    /// let pem = pubkey.to_public_key_pem().unwrap();
    /// assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----"));
    /// ```
    pub fn to_public_key_pem(&self) -> CrabResult<String> {
        use pkcs8::der::{Decode, EncodePem};

        let der = self.to_public_key_der()?;

        // Parse back to get the proper type for PEM encoding
        let spki = pkcs8::SubjectPublicKeyInfoRef::from_der(&der)
            .map_err(|e| CrabError::key_error(format!("Failed to parse DER: {}", e)))?;

        // Encode to PEM
        spki.to_pem(pkcs8::LineEnding::default())
            .map_err(|e| CrabError::key_error(format!("Failed to encode public key PEM: {}", e)))
    }

    /// Imports a public key from PEM format.
    ///
    /// # Example
    /// ```
    /// use crabgraph::asym::X25519KeyPair;
    ///
    /// let keypair = X25519KeyPair::generate().unwrap();
    /// let pubkey = keypair.public_key();
    /// let pem = pubkey.to_public_key_pem().unwrap();
    /// let restored = crabgraph::asym::X25519PublicKey::from_public_key_pem(&pem).unwrap();
    /// ```
    pub fn from_public_key_pem(pem: &str) -> CrabResult<Self> {
        // Use pkcs8::Document for proper PEM parsing
        let (_, doc) = pkcs8::Document::from_pem(pem)
            .map_err(|e| CrabError::key_error(format!("Failed to decode public key PEM: {}", e)))?;

        Self::from_public_key_der(doc.as_bytes())
    }
}

impl std::fmt::Debug for X25519KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X25519KeyPair")
            .field("public_key", &self.public_key())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x25519_generate() {
        let keypair = X25519KeyPair::generate().unwrap();
        let _public_key = keypair.public_key();
        assert_eq!(keypair.secret_bytes().len(), 32);
    }

    #[test]
    fn test_x25519_dh_exchange() {
        let alice = X25519KeyPair::generate().unwrap();
        let bob = X25519KeyPair::generate().unwrap();

        let alice_shared = alice.diffie_hellman(&bob.public_key()).unwrap();
        let bob_shared = bob.diffie_hellman(&alice.public_key()).unwrap();

        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn test_x25519_different_parties() {
        let alice = X25519KeyPair::generate().unwrap();
        let bob = X25519KeyPair::generate().unwrap();
        let charlie = X25519KeyPair::generate().unwrap();

        let alice_bob = alice.diffie_hellman(&bob.public_key()).unwrap();
        let alice_charlie = alice.diffie_hellman(&charlie.public_key()).unwrap();

        // Different shared secrets with different parties
        assert_ne!(alice_bob.as_bytes(), alice_charlie.as_bytes());
    }

    #[test]
    fn test_x25519_from_secret_bytes() {
        let keypair1 = X25519KeyPair::generate().unwrap();
        let secret = keypair1.secret_bytes();

        let keypair2 = X25519KeyPair::from_secret_bytes(secret).unwrap();

        // Same secret should produce same public key
        assert_eq!(keypair1.public_key().as_bytes(), keypair2.public_key().as_bytes());
    }

    #[test]
    fn test_x25519_public_key_serialization() {
        let keypair = X25519KeyPair::generate().unwrap();
        let public_key = keypair.public_key();

        // Base64
        let b64 = public_key.to_base64();
        let recovered = X25519PublicKey::from_base64(&b64).unwrap();
        assert_eq!(public_key.as_bytes(), recovered.as_bytes());

        // Hex
        let hex = public_key.to_hex();
        let recovered = X25519PublicKey::from_hex(&hex).unwrap();
        assert_eq!(public_key.as_bytes(), recovered.as_bytes());
    }

    #[test]
    fn test_x25519_derive_key() {
        let alice = X25519KeyPair::generate().unwrap();
        let bob = X25519KeyPair::generate().unwrap();

        let shared = alice.diffie_hellman(&bob.public_key()).unwrap();
        let key = shared.derive_key(b"test_app", 32).unwrap();

        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_x25519_derive_key_deterministic() {
        let alice = X25519KeyPair::generate().unwrap();
        let bob = X25519KeyPair::generate().unwrap();

        let shared = alice.diffie_hellman(&bob.public_key()).unwrap();
        let key1 = shared.derive_key(b"test_app", 32).unwrap();
        let key2 = shared.derive_key(b"test_app", 32).unwrap();

        assert_eq!(key1.as_slice(), key2.as_slice());
    }

    #[test]
    fn test_x25519_derive_key_different_info() {
        let alice = X25519KeyPair::generate().unwrap();
        let bob = X25519KeyPair::generate().unwrap();

        let shared = alice.diffie_hellman(&bob.public_key()).unwrap();
        let key1 = shared.derive_key(b"app1", 32).unwrap();
        let key2 = shared.derive_key(b"app2", 32).unwrap();

        assert_ne!(key1.as_slice(), key2.as_slice());
    }
}
