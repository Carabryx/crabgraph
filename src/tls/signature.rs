//! Signature verification algorithms for TLS certificate validation.
//!
//! This module provides the signature verification algorithms used to validate
//! TLS certificates and handshake signatures. It supports ECDSA, RSA, and Ed25519
//! signature schemes.

use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};
use rustls::SignatureScheme;

// ============================================================================
// Supported Signature Algorithms
// ============================================================================

/// WebPKI-compatible signature verification algorithms.
///
/// This static defines all signature algorithms supported for certificate
/// verification in TLS handshakes.
pub static SUPPORTED_SIG_ALGS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        // ECDSA algorithms (RFC 8446 compliant pairs only)
        ECDSA_P256_SHA256,
        ECDSA_P384_SHA384,
        // Ed25519
        ED25519,
        // RSA-PSS algorithms
        RSA_PSS_SHA256,
        RSA_PSS_SHA384,
        RSA_PSS_SHA512,
        // RSA PKCS#1 v1.5 algorithms
        RSA_PKCS1_SHA256,
        RSA_PKCS1_SHA384,
        RSA_PKCS1_SHA512,
    ],
    mapping: &[
        // ECDSA P-256 with SHA-256 (RFC 8446: ecdsa_secp256r1_sha256)
        (SignatureScheme::ECDSA_NISTP256_SHA256, &[ECDSA_P256_SHA256]),
        // ECDSA P-384 with SHA-384 (RFC 8446: ecdsa_secp384r1_sha384)
        (SignatureScheme::ECDSA_NISTP384_SHA384, &[ECDSA_P384_SHA384]),
        // Ed25519
        (SignatureScheme::ED25519, &[ED25519]),
        // RSA-PSS
        (SignatureScheme::RSA_PSS_SHA256, &[RSA_PSS_SHA256]),
        (SignatureScheme::RSA_PSS_SHA384, &[RSA_PSS_SHA384]),
        (SignatureScheme::RSA_PSS_SHA512, &[RSA_PSS_SHA512]),
        // RSA PKCS#1 v1.5
        (SignatureScheme::RSA_PKCS1_SHA256, &[RSA_PKCS1_SHA256]),
        (SignatureScheme::RSA_PKCS1_SHA384, &[RSA_PKCS1_SHA384]),
        (SignatureScheme::RSA_PKCS1_SHA512, &[RSA_PKCS1_SHA512]),
    ],
};

// ============================================================================
// ECDSA Signature Verification Algorithms
// ============================================================================

/// ECDSA P-256 with SHA-256 signature verification.
static ECDSA_P256_SHA256: &dyn SignatureVerificationAlgorithm = &EcdsaP256Sha256;

#[derive(Debug)]
struct EcdsaP256Sha256;

impl SignatureVerificationAlgorithm for EcdsaP256Sha256 {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        AlgorithmIdentifier::from_slice(ECDSA_P256_ALG_ID)
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        AlgorithmIdentifier::from_slice(ECDSA_SHA256_ALG_ID)
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        verify_ecdsa_p256_sha256(public_key, message, signature)
    }
}

/// ECDSA P-384 with SHA-384 signature verification.
static ECDSA_P384_SHA384: &dyn SignatureVerificationAlgorithm = &EcdsaP384Sha384;

#[derive(Debug)]
struct EcdsaP384Sha384;

impl SignatureVerificationAlgorithm for EcdsaP384Sha384 {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        AlgorithmIdentifier::from_slice(ECDSA_P384_ALG_ID)
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        AlgorithmIdentifier::from_slice(ECDSA_SHA384_ALG_ID)
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        verify_ecdsa_p384_sha384(public_key, message, signature)
    }
}

// ============================================================================
// Ed25519 Signature Verification Algorithm
// ============================================================================

/// Ed25519 signature verification.
static ED25519: &dyn SignatureVerificationAlgorithm = &Ed25519Verify;

#[derive(Debug)]
struct Ed25519Verify;

impl SignatureVerificationAlgorithm for Ed25519Verify {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        AlgorithmIdentifier::from_slice(ED25519_ALG_ID)
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        AlgorithmIdentifier::from_slice(ED25519_ALG_ID)
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        verify_ed25519(public_key, message, signature)
    }
}

// ============================================================================
// RSA-PSS Signature Verification Algorithms
// ============================================================================

/// RSA-PSS with SHA-256 signature verification.
static RSA_PSS_SHA256: &dyn SignatureVerificationAlgorithm = &RsaPssSha256;

#[derive(Debug)]
struct RsaPssSha256;

impl SignatureVerificationAlgorithm for RsaPssSha256 {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        AlgorithmIdentifier::from_slice(RSA_ALG_ID)
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        AlgorithmIdentifier::from_slice(RSA_PSS_SHA256_ALG_ID)
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        verify_rsa_pss::<sha2::Sha256>(public_key, message, signature)
    }
}

/// RSA-PSS with SHA-384 signature verification.
static RSA_PSS_SHA384: &dyn SignatureVerificationAlgorithm = &RsaPssSha384;

#[derive(Debug)]
struct RsaPssSha384;

impl SignatureVerificationAlgorithm for RsaPssSha384 {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        AlgorithmIdentifier::from_slice(RSA_ALG_ID)
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        AlgorithmIdentifier::from_slice(RSA_PSS_SHA384_ALG_ID)
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        verify_rsa_pss::<sha2::Sha384>(public_key, message, signature)
    }
}

/// RSA-PSS with SHA-512 signature verification.
static RSA_PSS_SHA512: &dyn SignatureVerificationAlgorithm = &RsaPssSha512;

#[derive(Debug)]
struct RsaPssSha512;

impl SignatureVerificationAlgorithm for RsaPssSha512 {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        AlgorithmIdentifier::from_slice(RSA_ALG_ID)
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        AlgorithmIdentifier::from_slice(RSA_PSS_SHA512_ALG_ID)
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        verify_rsa_pss::<sha2::Sha512>(public_key, message, signature)
    }
}

// ============================================================================
// RSA PKCS#1 v1.5 Signature Verification Algorithms
// ============================================================================

/// RSA PKCS#1 v1.5 with SHA-256 signature verification.
static RSA_PKCS1_SHA256: &dyn SignatureVerificationAlgorithm = &RsaPkcs1Sha256;

#[derive(Debug)]
struct RsaPkcs1Sha256;

impl SignatureVerificationAlgorithm for RsaPkcs1Sha256 {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        AlgorithmIdentifier::from_slice(RSA_ALG_ID)
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        AlgorithmIdentifier::from_slice(RSA_PKCS1_SHA256_ALG_ID)
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        verify_rsa_pkcs1::<sha2::Sha256>(public_key, message, signature)
    }
}

/// RSA PKCS#1 v1.5 with SHA-384 signature verification.
static RSA_PKCS1_SHA384: &dyn SignatureVerificationAlgorithm = &RsaPkcs1Sha384;

#[derive(Debug)]
struct RsaPkcs1Sha384;

impl SignatureVerificationAlgorithm for RsaPkcs1Sha384 {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        AlgorithmIdentifier::from_slice(RSA_ALG_ID)
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        AlgorithmIdentifier::from_slice(RSA_PKCS1_SHA384_ALG_ID)
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        verify_rsa_pkcs1::<sha2::Sha384>(public_key, message, signature)
    }
}

/// RSA PKCS#1 v1.5 with SHA-512 signature verification.
static RSA_PKCS1_SHA512: &dyn SignatureVerificationAlgorithm = &RsaPkcs1Sha512;

#[derive(Debug)]
struct RsaPkcs1Sha512;

impl SignatureVerificationAlgorithm for RsaPkcs1Sha512 {
    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        AlgorithmIdentifier::from_slice(RSA_ALG_ID)
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        AlgorithmIdentifier::from_slice(RSA_PKCS1_SHA512_ALG_ID)
    }

    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        verify_rsa_pkcs1::<sha2::Sha512>(public_key, message, signature)
    }
}

// ============================================================================
// Algorithm Identifiers (DER-encoded OIDs)
// ============================================================================

// ECDSA public key algorithm identifiers
// id-ecPublicKey (1.2.840.10045.2.1) + secp256r1 (1.2.840.10045.3.1.7)
const ECDSA_P256_ALG_ID: &[u8] = &[
    0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48,
    0xCE, 0x3D, 0x03, 0x01, 0x07,
];

// id-ecPublicKey (1.2.840.10045.2.1) + secp384r1 (1.3.132.0.34)
const ECDSA_P384_ALG_ID: &[u8] = &[
    0x30, 0x10, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x05, 0x2B, 0x81, 0x04,
    0x00, 0x22,
];

// ecdsa-with-SHA256 (1.2.840.10045.4.3.2)
const ECDSA_SHA256_ALG_ID: &[u8] =
    &[0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];

// ecdsa-with-SHA384 (1.2.840.10045.4.3.3)
const ECDSA_SHA384_ALG_ID: &[u8] =
    &[0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03];

// Ed25519 (1.3.101.112)
const ED25519_ALG_ID: &[u8] = &[0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70];

// RSA public key algorithm (1.2.840.113549.1.1.1)
const RSA_ALG_ID: &[u8] =
    &[0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00];

// RSA-PSS with SHA-256 (1.2.840.113549.1.1.10)
const RSA_PSS_SHA256_ALG_ID: &[u8] =
    &[0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A, 0x05, 0x00];

// RSA-PSS with SHA-384
const RSA_PSS_SHA384_ALG_ID: &[u8] = RSA_PSS_SHA256_ALG_ID;

// RSA-PSS with SHA-512
const RSA_PSS_SHA512_ALG_ID: &[u8] = RSA_PSS_SHA256_ALG_ID;

// RSA PKCS#1 v1.5 with SHA-256 (1.2.840.113549.1.1.11)
const RSA_PKCS1_SHA256_ALG_ID: &[u8] =
    &[0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00];

// RSA PKCS#1 v1.5 with SHA-384 (1.2.840.113549.1.1.12)
const RSA_PKCS1_SHA384_ALG_ID: &[u8] =
    &[0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0C, 0x05, 0x00];

// RSA PKCS#1 v1.5 with SHA-512 (1.2.840.113549.1.1.13)
const RSA_PKCS1_SHA512_ALG_ID: &[u8] =
    &[0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0D, 0x05, 0x00];

// ============================================================================
// Verification Implementation Functions
// ============================================================================

/// Verify an ECDSA P-256 signature with SHA-256.
fn verify_ecdsa_p256_sha256(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), InvalidSignature> {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    let verifying_key = VerifyingKey::from_sec1_bytes(public_key).map_err(|_| InvalidSignature)?;

    let sig = Signature::from_der(signature)
        .or_else(|_| Signature::from_slice(signature))
        .map_err(|_| InvalidSignature)?;

    verifying_key.verify(message, &sig).map_err(|_| InvalidSignature)
}

/// Verify an ECDSA P-384 signature with SHA-384.
fn verify_ecdsa_p384_sha384(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), InvalidSignature> {
    use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    let verifying_key = VerifyingKey::from_sec1_bytes(public_key).map_err(|_| InvalidSignature)?;

    let sig = Signature::from_der(signature)
        .or_else(|_| Signature::from_slice(signature))
        .map_err(|_| InvalidSignature)?;

    verifying_key.verify(message, &sig).map_err(|_| InvalidSignature)
}

/// Verify an Ed25519 signature.
fn verify_ed25519(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), InvalidSignature> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let public_key_bytes: [u8; 32] = public_key.try_into().map_err(|_| InvalidSignature)?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_key_bytes).map_err(|_| InvalidSignature)?;

    let sig_bytes: [u8; 64] = signature.try_into().map_err(|_| InvalidSignature)?;
    let sig = Signature::from_bytes(&sig_bytes);

    verifying_key.verify(message, &sig).map_err(|_| InvalidSignature)
}

/// Verify an RSA-PSS signature.
#[cfg(feature = "rsa-support")]
fn verify_rsa_pss<D>(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), InvalidSignature>
where
    D: sha2::Digest + digest::FixedOutputReset,
{
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::pss::{Signature, VerifyingKey};
    use rsa::signature::Verifier;
    use rsa::RsaPublicKey;

    // Try PKCS#1 DER format first, then try raw format
    let rsa_key = RsaPublicKey::from_pkcs1_der(public_key)
        .or_else(|_| {
            // Try parsing as SubjectPublicKeyInfo
            use rsa::pkcs8::DecodePublicKey;
            RsaPublicKey::from_public_key_der(public_key)
        })
        .map_err(|_| InvalidSignature)?;

    let verifying_key = VerifyingKey::<D>::new(rsa_key);
    let sig = Signature::try_from(signature).map_err(|_| InvalidSignature)?;

    verifying_key.verify(message, &sig).map_err(|_| InvalidSignature)
}

/// Verify an RSA-PSS signature (stub when RSA is disabled).
#[cfg(not(feature = "rsa-support"))]
fn verify_rsa_pss<D>(
    _public_key: &[u8],
    _message: &[u8],
    _signature: &[u8],
) -> Result<(), InvalidSignature>
where
    D: sha2::Digest + digest::FixedOutputReset,
{
    // RSA support not enabled
    Err(InvalidSignature)
}

/// Verify an RSA PKCS#1 v1.5 signature.
#[cfg(feature = "rsa-support")]
fn verify_rsa_pkcs1<D>(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), InvalidSignature>
where
    D: sha2::Digest + const_oid::AssociatedOid,
{
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::signature::Verifier;
    use rsa::RsaPublicKey;

    // Try PKCS#1 DER format first, then try SubjectPublicKeyInfo
    let rsa_key = RsaPublicKey::from_pkcs1_der(public_key)
        .or_else(|_| {
            use rsa::pkcs8::DecodePublicKey;
            RsaPublicKey::from_public_key_der(public_key)
        })
        .map_err(|_| InvalidSignature)?;

    let verifying_key = VerifyingKey::<D>::new(rsa_key);
    let sig = Signature::try_from(signature).map_err(|_| InvalidSignature)?;

    verifying_key.verify(message, &sig).map_err(|_| InvalidSignature)
}

/// Verify an RSA PKCS#1 v1.5 signature (stub when RSA is disabled).
#[cfg(not(feature = "rsa-support"))]
fn verify_rsa_pkcs1<D>(
    _public_key: &[u8],
    _message: &[u8],
    _signature: &[u8],
) -> Result<(), InvalidSignature>
where
    D: sha2::Digest + const_oid::AssociatedOid,
{
    // RSA support not enabled
    Err(InvalidSignature)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supported_sig_algs_not_empty() {
        assert!(!SUPPORTED_SIG_ALGS.all.is_empty());
        assert!(!SUPPORTED_SIG_ALGS.mapping.is_empty());
    }

    #[test]
    fn test_all_algorithms_count() {
        // 2 ECDSA (RFC 8446 compliant) + 1 Ed25519 + 3 RSA-PSS + 3 RSA PKCS#1 = 9 total
        assert_eq!(SUPPORTED_SIG_ALGS.all.len(), 9);
    }

    #[test]
    fn test_mapping_covers_all_tls_schemes() {
        // Verify we have mappings for all important signature schemes
        let schemes: Vec<_> = SUPPORTED_SIG_ALGS.mapping.iter().map(|(s, _)| *s).collect();

        assert!(schemes.contains(&SignatureScheme::ECDSA_NISTP256_SHA256));
        assert!(schemes.contains(&SignatureScheme::ECDSA_NISTP384_SHA384));
        assert!(schemes.contains(&SignatureScheme::ED25519));
        assert!(schemes.contains(&SignatureScheme::RSA_PSS_SHA256));
        assert!(schemes.contains(&SignatureScheme::RSA_PSS_SHA384));
        assert!(schemes.contains(&SignatureScheme::RSA_PSS_SHA512));
        assert!(schemes.contains(&SignatureScheme::RSA_PKCS1_SHA256));
        assert!(schemes.contains(&SignatureScheme::RSA_PKCS1_SHA384));
        assert!(schemes.contains(&SignatureScheme::RSA_PKCS1_SHA512));
    }

    #[test]
    fn test_ed25519_verification() {
        use ed25519_dalek::{Signer, SigningKey};

        // Generate a keypair
        let mut rng = rand_core::OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();

        // Sign a message
        let message = b"Test message for Ed25519";
        let signature = signing_key.sign(message);

        // Verify using our implementation
        let result = verify_ed25519(verifying_key.as_bytes(), message, &signature.to_bytes());

        assert!(result.is_ok());
    }

    #[test]
    fn test_ed25519_verification_wrong_message() {
        use ed25519_dalek::{Signer, SigningKey};

        let mut rng = rand_core::OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();

        let message = b"Original message";
        let signature = signing_key.sign(message);

        // Verify with wrong message
        let result =
            verify_ed25519(verifying_key.as_bytes(), b"Wrong message", &signature.to_bytes());

        assert!(result.is_err());
    }

    #[test]
    fn test_ecdsa_p256_verification() {
        use p256::ecdsa::{signature::Signer, SigningKey};

        let mut rng = rand_core::OsRng;
        let signing_key = SigningKey::random(&mut rng);
        let verifying_key = signing_key.verifying_key();

        let message = b"Test message for P-256 ECDSA";
        let signature: p256::ecdsa::Signature = signing_key.sign(message);

        let result = verify_ecdsa_p256_sha256(
            &verifying_key.to_sec1_bytes(),
            message,
            signature.to_der().as_bytes(),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_ecdsa_p384_verification() {
        use p384::ecdsa::{signature::Signer, SigningKey};

        let mut rng = rand_core::OsRng;
        let signing_key = SigningKey::random(&mut rng);
        let verifying_key = signing_key.verifying_key();

        let message = b"Test message for P-384 ECDSA";
        let signature: p384::ecdsa::Signature = signing_key.sign(message);

        let result = verify_ecdsa_p384_sha384(
            &verifying_key.to_sec1_bytes(),
            message,
            signature.to_der().as_bytes(),
        );

        assert!(result.is_ok());
    }
}
