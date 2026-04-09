//! TLS 1.3 cipher suite definitions.
//!
//! This module defines the TLS 1.3 cipher suites supported by crabgraph:
//! - TLS_AES_128_GCM_SHA256
//! - TLS_AES_256_GCM_SHA384
//! - TLS_CHACHA20_POLY1305_SHA256

use super::aead;
use super::hash;
use super::hmac;

use rustls::crypto::tls13::HkdfUsingHmac;
use rustls::CipherSuiteCommon;
use rustls::{CipherSuite, SupportedCipherSuite, Tls13CipherSuite};

/// All supported TLS 1.3 cipher suites, in order of preference.
///
/// The order reflects:
/// 1. AES-256-GCM for maximum security
/// 2. ChaCha20-Poly1305 for environments without AES-NI
/// 3. AES-128-GCM for compatibility
pub static ALL_TLS13_CIPHER_SUITES: &[&Tls13CipherSuite] =
    &[TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256, TLS13_AES_128_GCM_SHA256];

/// All TLS 1.3 cipher suites as SupportedCipherSuite for CryptoProvider.
pub static ALL_TLS13_SUITES: &[SupportedCipherSuite] = &[
    SupportedCipherSuite::Tls13(TLS13_AES_256_GCM_SHA384),
    SupportedCipherSuite::Tls13(TLS13_CHACHA20_POLY1305_SHA256),
    SupportedCipherSuite::Tls13(TLS13_AES_128_GCM_SHA256),
];

// ============================================================================
// TLS_AES_128_GCM_SHA256
// ============================================================================

/// TLS 1.3 AES-128-GCM with SHA-256 cipher suite.
///
/// This is the mandatory-to-implement cipher suite for TLS 1.3 per RFC 8446.
/// Uses AES-128-GCM for encryption and SHA-256 for HKDF operations.
pub static TLS13_AES_128_GCM_SHA256: &Tls13CipherSuite = &Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
        hash_provider: &hash::Sha256Hash,
        // Per IETF draft-irtf-cfrg-aead-limits, AES-GCM has 2^23 confidentiality limit
        confidentiality_limit: 1 << 23,
    },
    hkdf_provider: &HkdfUsingHmac(&hmac::HmacSha256),
    aead_alg: &aead::AES_128_GCM,
    quic: None,
};

// ============================================================================
// TLS_AES_256_GCM_SHA384
// ============================================================================

/// TLS 1.3 AES-256-GCM with SHA-384 cipher suite.
///
/// Provides stronger security than AES-128 with 256-bit keys.
/// Uses SHA-384 for HKDF operations.
pub static TLS13_AES_256_GCM_SHA384: &Tls13CipherSuite = &Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
        hash_provider: &hash::Sha384Hash,
        confidentiality_limit: 1 << 23,
    },
    hkdf_provider: &HkdfUsingHmac(&hmac::HmacSha384),
    aead_alg: &aead::AES_256_GCM,
    quic: None,
};

// ============================================================================
// TLS_CHACHA20_POLY1305_SHA256
// ============================================================================

/// TLS 1.3 ChaCha20-Poly1305 with SHA-256 cipher suite.
///
/// ChaCha20-Poly1305 is preferred on systems without hardware AES acceleration
/// (AES-NI), providing consistent performance across all platforms.
/// Uses SHA-256 for HKDF operations.
pub static TLS13_CHACHA20_POLY1305_SHA256: &Tls13CipherSuite = &Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        hash_provider: &hash::Sha256Hash,
        // ChaCha20-Poly1305 has no practical confidentiality limit
        confidentiality_limit: u64::MAX,
    },
    hkdf_provider: &HkdfUsingHmac(&hmac::HmacSha256),
    aead_alg: &aead::CHACHA20_POLY1305,
    quic: None,
};

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls13_cipher_suite_count() {
        assert_eq!(ALL_TLS13_CIPHER_SUITES.len(), 3);
    }

    #[test]
    fn test_tls13_aes_128_gcm_sha256() {
        let suite = TLS13_AES_128_GCM_SHA256;
        assert_eq!(suite.common.suite, CipherSuite::TLS13_AES_128_GCM_SHA256);
    }

    #[test]
    fn test_tls13_aes_256_gcm_sha384() {
        let suite = TLS13_AES_256_GCM_SHA384;
        assert_eq!(suite.common.suite, CipherSuite::TLS13_AES_256_GCM_SHA384);
    }

    #[test]
    fn test_tls13_chacha20_poly1305_sha256() {
        let suite = TLS13_CHACHA20_POLY1305_SHA256;
        assert_eq!(suite.common.suite, CipherSuite::TLS13_CHACHA20_POLY1305_SHA256);
    }

    #[test]
    fn test_all_suites_length() {
        assert_eq!(ALL_TLS13_SUITES.len(), 3);
    }

    #[test]
    fn test_cipher_suite_order() {
        // Verify our preference order: AES-256 > ChaCha20 > AES-128
        let suites = ALL_TLS13_CIPHER_SUITES;
        assert_eq!(suites[0].common.suite, CipherSuite::TLS13_AES_256_GCM_SHA384);
        assert_eq!(suites[1].common.suite, CipherSuite::TLS13_CHACHA20_POLY1305_SHA256);
        assert_eq!(suites[2].common.suite, CipherSuite::TLS13_AES_128_GCM_SHA256);
    }

    #[test]
    fn test_all_tls13_suites_are_tls13() {
        // All TLS 1.3 suites should have TLS 1.3-only cipher suites
        for suite in ALL_TLS13_CIPHER_SUITES {
            // Verify they're all TLS 1.3 cipher suites (naming convention)
            let name = format!("{:?}", suite.common.suite);
            assert!(name.starts_with("TLS13_"), "Expected TLS 1.3 suite, got {}", name);
        }
    }

    #[test]
    fn test_confidentiality_limits() {
        // AES-GCM should have 2^23 limit
        assert_eq!(TLS13_AES_128_GCM_SHA256.common.confidentiality_limit, 1 << 23);
        assert_eq!(TLS13_AES_256_GCM_SHA384.common.confidentiality_limit, 1 << 23);
        // ChaCha20-Poly1305 has no practical limit
        assert_eq!(TLS13_CHACHA20_POLY1305_SHA256.common.confidentiality_limit, u64::MAX);
    }
}
