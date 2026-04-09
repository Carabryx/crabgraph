//! Key provider for loading TLS private keys.
//!
//! This module implements the `KeyProvider` trait for loading private signing keys
//! from various formats (PKCS#8, SEC1, PKCS#1) for use in TLS connections.

use rustls::crypto::KeyProvider;
use rustls::pki_types::PrivateKeyDer;
use rustls::sign::SigningKey;
use rustls::SignatureAlgorithm;
use rustls::SignatureScheme;

use std::sync::Arc;

/// Crabgraph key provider for loading private keys.
#[derive(Debug)]
pub struct CrabKeyProvider;

impl KeyProvider for CrabKeyProvider {
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn SigningKey>, rustls::Error> {
        match &key_der {
            PrivateKeyDer::Pkcs8(der) => {
                // Try ECDSA keys first (most common in modern TLS)
                if let Ok(key) = EcdsaSigningKey::from_pkcs8_der(der.secret_pkcs8_der()) {
                    return Ok(Arc::new(key));
                }
                // Try Ed25519
                if let Ok(key) = Ed25519SigningKey::from_pkcs8_der(der.secret_pkcs8_der()) {
                    return Ok(Arc::new(key));
                }
                // Try RSA
                #[cfg(feature = "rsa-support")]
                if let Ok(key) = RsaSigningKey::from_pkcs8_der(der.secret_pkcs8_der()) {
                    return Ok(Arc::new(key));
                }
                Err(rustls::Error::General("unsupported PKCS#8 key type".into()))
            }
            PrivateKeyDer::Sec1(der) => {
                // SEC1 is specifically for EC keys
                if let Ok(key) = EcdsaSigningKey::from_sec1_der(der.secret_sec1_der()) {
                    return Ok(Arc::new(key));
                }
                Err(rustls::Error::General("unsupported SEC1 key".into()))
            }
            PrivateKeyDer::Pkcs1(der) => {
                // PKCS#1 is specifically for RSA keys
                #[cfg(feature = "rsa-support")]
                {
                    if let Ok(key) = RsaSigningKey::from_pkcs1_der(der.secret_pkcs1_der()) {
                        return Ok(Arc::new(key));
                    }
                }
                #[cfg(not(feature = "rsa-support"))]
                let _ = der;
                Err(rustls::Error::General("PKCS#1 RSA keys require rsa-support feature".into()))
            }
            _ => Err(rustls::Error::General("unsupported key format".into())),
        }
    }
}

// ============================================================================
// ECDSA Signing Key
// ============================================================================

/// ECDSA signing key supporting P-256 and P-384 curves.
pub struct EcdsaSigningKey {
    inner: EcdsaKeyInner,
    scheme: SignatureScheme,
}

enum EcdsaKeyInner {
    P256(p256::ecdsa::SigningKey),
    P384(p384::ecdsa::SigningKey),
}

impl EcdsaSigningKey {
    /// Parse an ECDSA key from PKCS#8 DER format.
    #[allow(unused_imports)]
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, rustls::Error> {
        use p256::pkcs8::DecodePrivateKey as _;
        use p384::pkcs8::DecodePrivateKey as _;

        // Try P-256 first
        if let Ok(key) = p256::ecdsa::SigningKey::from_pkcs8_der(der) {
            return Ok(Self {
                inner: EcdsaKeyInner::P256(key),
                scheme: SignatureScheme::ECDSA_NISTP256_SHA256,
            });
        }
        // Try P-384
        if let Ok(key) = p384::ecdsa::SigningKey::from_pkcs8_der(der) {
            return Ok(Self {
                inner: EcdsaKeyInner::P384(key),
                scheme: SignatureScheme::ECDSA_NISTP384_SHA384,
            });
        }
        Err(rustls::Error::General("failed to parse ECDSA key from PKCS#8".into()))
    }

    /// Parse an ECDSA key from SEC1 DER format.
    ///
    /// SEC1 DER contains an ASN.1 `ECPrivateKey` structure (not raw scalar bytes).
    /// Falls back to raw scalar parsing if SEC1 DER decoding fails, supporting
    /// both formats.
    pub fn from_sec1_der(der: &[u8]) -> Result<Self, rustls::Error> {
        // Try P-256 SEC1 DER first, then fall back to raw scalar
        if let Ok(secret_key) = p256::SecretKey::from_sec1_der(der) {
            let key: p256::ecdsa::SigningKey = secret_key.into();
            return Ok(Self {
                inner: EcdsaKeyInner::P256(key),
                scheme: SignatureScheme::ECDSA_NISTP256_SHA256,
            });
        }
        if let Ok(key) = p256::ecdsa::SigningKey::from_slice(der) {
            return Ok(Self {
                inner: EcdsaKeyInner::P256(key),
                scheme: SignatureScheme::ECDSA_NISTP256_SHA256,
            });
        }
        // Try P-384 SEC1 DER first, then fall back to raw scalar
        if let Ok(secret_key) = p384::SecretKey::from_sec1_der(der) {
            let key: p384::ecdsa::SigningKey = secret_key.into();
            return Ok(Self {
                inner: EcdsaKeyInner::P384(key),
                scheme: SignatureScheme::ECDSA_NISTP384_SHA384,
            });
        }
        if let Ok(key) = p384::ecdsa::SigningKey::from_slice(der) {
            return Ok(Self {
                inner: EcdsaKeyInner::P384(key),
                scheme: SignatureScheme::ECDSA_NISTP384_SHA384,
            });
        }
        Err(rustls::Error::General("failed to parse ECDSA key from SEC1".into()))
    }
}

impl std::fmt::Debug for EcdsaSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EcdsaSigningKey")
            .field("scheme", &self.scheme)
            .finish_non_exhaustive()
    }
}

impl SigningKey for EcdsaSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
        if offered.contains(&self.scheme) {
            Some(Box::new(EcdsaSigner {
                key: match &self.inner {
                    EcdsaKeyInner::P256(k) => EcdsaKeyInner::P256(k.clone()),
                    EcdsaKeyInner::P384(k) => EcdsaKeyInner::P384(k.clone()),
                },
                scheme: self.scheme,
            }))
        } else {
            None
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        match self.scheme {
            SignatureScheme::ECDSA_NISTP256_SHA256 => SignatureAlgorithm::ECDSA,
            SignatureScheme::ECDSA_NISTP384_SHA384 => SignatureAlgorithm::ECDSA,
            _ => SignatureAlgorithm::Unknown(0),
        }
    }
}

struct EcdsaSigner {
    key: EcdsaKeyInner,
    scheme: SignatureScheme,
}

impl std::fmt::Debug for EcdsaSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EcdsaSigner")
            .field("scheme", &self.scheme)
            .finish_non_exhaustive()
    }
}

impl rustls::sign::Signer for EcdsaSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        use ecdsa::signature::Signer;

        match &self.key {
            EcdsaKeyInner::P256(key) => {
                let sig: p256::ecdsa::Signature = key.sign(message);
                Ok(sig.to_der().as_bytes().to_vec())
            }
            EcdsaKeyInner::P384(key) => {
                let sig: p384::ecdsa::Signature = key.sign(message);
                Ok(sig.to_der().as_bytes().to_vec())
            }
        }
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

// ============================================================================
// Ed25519 Signing Key
// ============================================================================

/// Ed25519 signing key.
pub struct Ed25519SigningKey {
    key: ed25519_dalek::SigningKey,
}

impl Ed25519SigningKey {
    /// Parse an Ed25519 key from PKCS#8 DER format.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, rustls::Error> {
        use ed25519_dalek::pkcs8::DecodePrivateKey;
        let key = ed25519_dalek::SigningKey::from_pkcs8_der(der).map_err(|_| {
            rustls::Error::General("failed to parse Ed25519 key from PKCS#8".into())
        })?;
        Ok(Self {
            key,
        })
    }
}

impl std::fmt::Debug for Ed25519SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ed25519SigningKey").finish_non_exhaustive()
    }
}

impl SigningKey for Ed25519SigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
        if offered.contains(&SignatureScheme::ED25519) {
            Some(Box::new(Ed25519Signer {
                key: self.key.clone(),
            }))
        } else {
            None
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ED25519
    }
}

struct Ed25519Signer {
    key: ed25519_dalek::SigningKey,
}

impl std::fmt::Debug for Ed25519Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ed25519Signer").finish_non_exhaustive()
    }
}

impl rustls::sign::Signer for Ed25519Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        use ed25519_dalek::Signer;
        let sig = self.key.sign(message);
        Ok(sig.to_bytes().to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

// ============================================================================
// RSA Signing Key (feature-gated)
// ============================================================================

#[cfg(feature = "rsa-support")]
mod rsa_impl {
    use super::*;
    use rsa::pkcs1v15::SigningKey as RsaPkcs1SigningKey;
    use rsa::pss::BlindedSigningKey;
    use rsa::signature::SignatureEncoding;
    use rsa::RsaPrivateKey;
    use sha2::{Sha256, Sha384, Sha512};

    /// RSA signing key supporting PKCS#1 v1.5 and PSS schemes.
    pub struct RsaSigningKey {
        key: RsaPrivateKey,
    }

    impl RsaSigningKey {
        /// Parse an RSA key from PKCS#8 DER format.
        pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, rustls::Error> {
            use rsa::pkcs8::DecodePrivateKey;
            let key = RsaPrivateKey::from_pkcs8_der(der).map_err(|_| {
                rustls::Error::General("failed to parse RSA key from PKCS#8".into())
            })?;
            Ok(Self {
                key,
            })
        }

        /// Parse an RSA key from PKCS#1 DER format.
        pub fn from_pkcs1_der(der: &[u8]) -> Result<Self, rustls::Error> {
            use rsa::pkcs1::DecodeRsaPrivateKey;
            let key = RsaPrivateKey::from_pkcs1_der(der).map_err(|_| {
                rustls::Error::General("failed to parse RSA key from PKCS#1".into())
            })?;
            Ok(Self {
                key,
            })
        }
    }

    impl std::fmt::Debug for RsaSigningKey {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("RsaSigningKey").finish_non_exhaustive()
        }
    }

    impl SigningKey for RsaSigningKey {
        fn choose_scheme(
            &self,
            offered: &[SignatureScheme],
        ) -> Option<Box<dyn rustls::sign::Signer>> {
            // Prefer PSS over PKCS#1, prefer SHA-512 > SHA-384 > SHA-256
            let schemes = [
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::RSA_PKCS1_SHA256,
            ];

            for scheme in schemes {
                if offered.contains(&scheme) {
                    return Some(Box::new(RsaSigner {
                        key: self.key.clone(),
                        scheme,
                    }));
                }
            }
            None
        }

        fn algorithm(&self) -> SignatureAlgorithm {
            SignatureAlgorithm::RSA
        }
    }

    struct RsaSigner {
        key: RsaPrivateKey,
        scheme: SignatureScheme,
    }

    impl std::fmt::Debug for RsaSigner {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("RsaSigner")
                .field("scheme", &self.scheme)
                .finish_non_exhaustive()
        }
    }

    impl rustls::sign::Signer for RsaSigner {
        fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
            use rsa::signature::RandomizedSigner;

            let mut rng = rand::rngs::OsRng;

            match self.scheme {
                SignatureScheme::RSA_PSS_SHA256 => {
                    let signer = BlindedSigningKey::<Sha256>::new(self.key.clone());
                    let sig = signer
                        .try_sign_with_rng(&mut rng, message)
                        .map_err(|_| rustls::Error::General("RSA-PSS signing failed".into()))?;
                    Ok(sig.to_vec())
                }
                SignatureScheme::RSA_PSS_SHA384 => {
                    let signer = BlindedSigningKey::<Sha384>::new(self.key.clone());
                    let sig = signer
                        .try_sign_with_rng(&mut rng, message)
                        .map_err(|_| rustls::Error::General("RSA-PSS signing failed".into()))?;
                    Ok(sig.to_vec())
                }
                SignatureScheme::RSA_PSS_SHA512 => {
                    let signer = BlindedSigningKey::<Sha512>::new(self.key.clone());
                    let sig = signer
                        .try_sign_with_rng(&mut rng, message)
                        .map_err(|_| rustls::Error::General("RSA-PSS signing failed".into()))?;
                    Ok(sig.to_vec())
                }
                SignatureScheme::RSA_PKCS1_SHA256 => {
                    use rsa::signature::Signer;
                    let signer = RsaPkcs1SigningKey::<Sha256>::new(self.key.clone());
                    let sig = signer
                        .try_sign(message)
                        .map_err(|_| rustls::Error::General("RSA-PKCS1 signing failed".into()))?;
                    Ok(sig.to_vec())
                }
                SignatureScheme::RSA_PKCS1_SHA384 => {
                    use rsa::signature::Signer;
                    let signer = RsaPkcs1SigningKey::<Sha384>::new(self.key.clone());
                    let sig = signer
                        .try_sign(message)
                        .map_err(|_| rustls::Error::General("RSA-PKCS1 signing failed".into()))?;
                    Ok(sig.to_vec())
                }
                SignatureScheme::RSA_PKCS1_SHA512 => {
                    use rsa::signature::Signer;
                    let signer = RsaPkcs1SigningKey::<Sha512>::new(self.key.clone());
                    let sig = signer
                        .try_sign(message)
                        .map_err(|_| rustls::Error::General("RSA-PKCS1 signing failed".into()))?;
                    Ok(sig.to_vec())
                }
                _ => Err(rustls::Error::General("unsupported RSA scheme".into())),
            }
        }

        fn scheme(&self) -> SignatureScheme {
            self.scheme
        }
    }
}

#[cfg(feature = "rsa-support")]
pub use rsa_impl::RsaSigningKey;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_provider_debug() {
        let provider = CrabKeyProvider;
        assert!(format!("{:?}", provider).contains("CrabKeyProvider"));
    }

    #[test]
    fn test_ecdsa_p256_key_generation_and_signing() {
        use p256::ecdsa::SigningKey;
        use p256::pkcs8::EncodePrivateKey;

        let mut rng = rand_core::OsRng;
        let signing_key = SigningKey::random(&mut rng);

        // Export to PKCS#8
        let pkcs8_der = signing_key.to_pkcs8_der().expect("Failed to encode PKCS#8");

        // Load via our key provider
        let loaded = EcdsaSigningKey::from_pkcs8_der(pkcs8_der.as_bytes())
            .expect("Failed to load PKCS#8 key");

        // Sign a message
        let offered = [SignatureScheme::ECDSA_NISTP256_SHA256];
        let signer = loaded.choose_scheme(&offered).expect("Should choose scheme");

        let message = b"Test message";
        let signature = signer.sign(message).expect("Should sign");

        assert!(!signature.is_empty());
    }

    #[test]
    fn test_ed25519_key_generation_and_signing() {
        use ed25519_dalek::pkcs8::EncodePrivateKey;

        let mut rng = rand_core::OsRng;
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rng);

        // Export to PKCS#8
        let pkcs8_der = signing_key.to_pkcs8_der().expect("Failed to encode PKCS#8");

        // Load via our key provider
        let loaded = Ed25519SigningKey::from_pkcs8_der(pkcs8_der.as_bytes())
            .expect("Failed to load PKCS#8 key");

        // Sign a message
        let offered = [SignatureScheme::ED25519];
        let signer = loaded.choose_scheme(&offered).expect("Should choose scheme");

        let message = b"Test message";
        let signature = signer.sign(message).expect("Should sign");

        assert_eq!(signature.len(), 64); // Ed25519 signatures are 64 bytes
    }
}
