//! TLS 1.2 cipher suite definitions.
//!
//! This module defines the TLS 1.2 cipher suites supported by crabgraph:
//! - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
//! - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
//! - TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
//! - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
//! - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
//! - TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256

use super::aead;
use super::hash;
use super::hmac;

use rustls::crypto::tls12::PrfUsingHmac;
use rustls::crypto::KeyExchangeAlgorithm;
use rustls::CipherSuiteCommon;
use rustls::{CipherSuite, SignatureScheme, SupportedCipherSuite, Tls12CipherSuite};

/// All supported TLS 1.2 cipher suites, in order of preference.
///
/// ECDSA suites are preferred over RSA for better performance.
/// AES-256 is preferred for maximum security, followed by ChaCha20 for
/// environments without AES-NI.
pub static ALL_TLS12_CIPHER_SUITES: &[&Tls12CipherSuite] = &[
    // ECDSA suites (preferred)
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    // RSA suites
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
];

/// All TLS 1.2 cipher suites as SupportedCipherSuite for CryptoProvider.
pub static ALL_TLS12_SUITES: &[SupportedCipherSuite] = &[
    SupportedCipherSuite::Tls12(TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384),
    SupportedCipherSuite::Tls12(TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256),
    SupportedCipherSuite::Tls12(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
    SupportedCipherSuite::Tls12(TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384),
    SupportedCipherSuite::Tls12(TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256),
    SupportedCipherSuite::Tls12(TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
];

// ============================================================================
// ECDSA Cipher Suites
// ============================================================================

/// TLS 1.2 ECDHE-ECDSA with AES-128-GCM and SHA-256.
pub static TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: &Tls12CipherSuite = &Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        hash_provider: &hash::Sha256Hash,
        confidentiality_limit: 1 << 23,
    },
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: &TLS12_ECDSA_SCHEMES,
    aead_alg: &aead::AES_128_GCM_TLS12,
    prf_provider: &PrfUsingHmac(&hmac::HmacSha256),
};

/// TLS 1.2 ECDHE-ECDSA with AES-256-GCM and SHA-384.
pub static TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: &Tls12CipherSuite = &Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        hash_provider: &hash::Sha384Hash,
        confidentiality_limit: 1 << 23,
    },
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: &TLS12_ECDSA_SCHEMES,
    aead_alg: &aead::AES_256_GCM_TLS12,
    prf_provider: &PrfUsingHmac(&hmac::HmacSha384),
};

/// TLS 1.2 ECDHE-ECDSA with ChaCha20-Poly1305 and SHA-256.
pub static TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: &Tls12CipherSuite = &Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        hash_provider: &hash::Sha256Hash,
        confidentiality_limit: u64::MAX,
    },
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: &TLS12_ECDSA_SCHEMES,
    aead_alg: &aead::CHACHA20_POLY1305_TLS12,
    prf_provider: &PrfUsingHmac(&hmac::HmacSha256),
};

// ============================================================================
// RSA Cipher Suites
// ============================================================================

/// TLS 1.2 ECDHE-RSA with AES-128-GCM and SHA-256.
pub static TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: &Tls12CipherSuite = &Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        hash_provider: &hash::Sha256Hash,
        confidentiality_limit: 1 << 23,
    },
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: &TLS12_RSA_SCHEMES,
    aead_alg: &aead::AES_128_GCM_TLS12,
    prf_provider: &PrfUsingHmac(&hmac::HmacSha256),
};

/// TLS 1.2 ECDHE-RSA with AES-256-GCM and SHA-384.
pub static TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: &Tls12CipherSuite = &Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        hash_provider: &hash::Sha384Hash,
        confidentiality_limit: 1 << 23,
    },
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: &TLS12_RSA_SCHEMES,
    aead_alg: &aead::AES_256_GCM_TLS12,
    prf_provider: &PrfUsingHmac(&hmac::HmacSha384),
};

/// TLS 1.2 ECDHE-RSA with ChaCha20-Poly1305 and SHA-256.
pub static TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: &Tls12CipherSuite = &Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        hash_provider: &hash::Sha256Hash,
        confidentiality_limit: u64::MAX,
    },
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: &TLS12_RSA_SCHEMES,
    aead_alg: &aead::CHACHA20_POLY1305_TLS12,
    prf_provider: &PrfUsingHmac(&hmac::HmacSha256),
};

// ============================================================================
// Signature Schemes
// ============================================================================

/// ECDSA signature schemes for TLS 1.2.
pub static TLS12_ECDSA_SCHEMES: [SignatureScheme; 2] =
    [SignatureScheme::ECDSA_NISTP384_SHA384, SignatureScheme::ECDSA_NISTP256_SHA256];

/// RSA signature schemes for TLS 1.2.
pub static TLS12_RSA_SCHEMES: [SignatureScheme; 6] = [
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
];

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls12_cipher_suite_count() {
        assert_eq!(ALL_TLS12_CIPHER_SUITES.len(), 6);
    }

    #[test]
    fn test_tls12_ecdsa_aes_128() {
        let suite = TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
        assert_eq!(suite.common.suite, CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
        assert_eq!(suite.kx, KeyExchangeAlgorithm::ECDHE);
    }

    #[test]
    fn test_tls12_ecdsa_aes_256() {
        let suite = TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384;
        assert_eq!(suite.common.suite, CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
    }

    #[test]
    fn test_tls12_rsa_aes_128() {
        let suite = TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
        assert_eq!(suite.common.suite, CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
    }

    #[test]
    fn test_tls12_rsa_aes_256() {
        let suite = TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384;
        assert_eq!(suite.common.suite, CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
    }

    #[test]
    fn test_tls12_chacha_suites() {
        let ecdsa = TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256;
        let rsa = TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256;

        assert_eq!(ecdsa.common.suite, CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256);
        assert_eq!(rsa.common.suite, CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
    }

    #[test]
    fn test_all_suites_length() {
        assert_eq!(ALL_TLS12_SUITES.len(), 6);
    }

    #[test]
    fn test_signature_schemes() {
        assert_eq!(TLS12_ECDSA_SCHEMES.len(), 2);
        assert_eq!(TLS12_RSA_SCHEMES.len(), 6);
    }

    #[test]
    fn test_cipher_suite_order() {
        // ECDSA suites should come before RSA suites
        let suites = ALL_TLS12_CIPHER_SUITES;

        // First 3 should be ECDSA
        assert_eq!(suites[0].common.suite, CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
        assert_eq!(
            suites[1].common.suite,
            CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        );
        assert_eq!(suites[2].common.suite, CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);

        // Last 3 should be RSA
        assert_eq!(suites[3].common.suite, CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
        assert_eq!(
            suites[4].common.suite,
            CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        );
        assert_eq!(suites[5].common.suite, CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
    }
}
