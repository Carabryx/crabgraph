//! HMAC, HKDF, and PRF implementations for TLS.

use hmac::{Mac, SimpleHmac};
use rustls::crypto::hmac::{Hmac, Key, Tag};
use rustls::crypto::tls12::Prf;
use rustls::crypto::tls13::{Hkdf, HkdfExpander, OkmBlock, OutputLengthError};
use sha2::{Sha256, Sha384};

/// HMAC-SHA256 for TLS.
pub static HMAC_SHA256: &dyn Hmac = &HmacSha256;

/// HMAC-SHA384 for TLS.
pub static HMAC_SHA384: &dyn Hmac = &HmacSha384;

// ============================================================================
// HMAC Implementations
// ============================================================================

/// HMAC-SHA256 implementation for TLS.
#[derive(Debug)]
pub struct HmacSha256;

impl Hmac for HmacSha256 {
    fn with_key(&self, key: &[u8]) -> Box<dyn Key> {
        // HMAC spec (RFC 2104) accepts any key length: keys shorter than the
        // block size are zero-padded, longer keys are hashed first.
        // SimpleHmac::new_from_slice therefore never returns an error.
        Box::new(HmacSha256Key(
            SimpleHmac::<Sha256>::new_from_slice(key).expect("HMAC key should be valid"),
        ))
    }

    fn hash_output_len(&self) -> usize {
        32
    }
}

struct HmacSha256Key(SimpleHmac<Sha256>);

impl Key for HmacSha256Key {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> Tag {
        let mut hmac = self.0.clone();
        hmac.update(first);
        for m in middle {
            hmac.update(m);
        }
        hmac.update(last);
        Tag::new(&hmac.finalize().into_bytes()[..])
    }

    fn tag_len(&self) -> usize {
        32
    }
}

/// HMAC-SHA384 implementation for TLS.
#[derive(Debug)]
pub struct HmacSha384;

impl Hmac for HmacSha384 {
    fn with_key(&self, key: &[u8]) -> Box<dyn Key> {
        // HMAC spec (RFC 2104) accepts any key length: keys shorter than the
        // block size are zero-padded, longer keys are hashed first.
        // SimpleHmac::new_from_slice therefore never returns an error.
        Box::new(HmacSha384Key(
            SimpleHmac::<Sha384>::new_from_slice(key).expect("HMAC key should be valid"),
        ))
    }

    fn hash_output_len(&self) -> usize {
        48
    }
}

struct HmacSha384Key(SimpleHmac<Sha384>);

impl Key for HmacSha384Key {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> Tag {
        let mut hmac = self.0.clone();
        hmac.update(first);
        for m in middle {
            hmac.update(m);
        }
        hmac.update(last);
        Tag::new(&hmac.finalize().into_bytes()[..])
    }

    fn tag_len(&self) -> usize {
        48
    }
}

// ============================================================================
// TLS 1.3 HKDF Implementations
// ============================================================================

/// HKDF-SHA256 for TLS 1.3.
#[derive(Debug)]
pub struct HkdfSha256;

impl Hkdf for HkdfSha256 {
    fn extract_from_zero_ikm(&self, salt: Option<&[u8]>) -> Box<dyn HkdfExpander> {
        let salt = salt.unwrap_or(&[0u8; 32]);
        let (prk, _) = hkdf::Hkdf::<Sha256>::extract(Some(salt), &[0u8; 32]);
        Box::new(HkdfSha256Expander {
            prk,
        })
    }

    fn extract_from_secret(&self, salt: Option<&[u8]>, secret: &[u8]) -> Box<dyn HkdfExpander> {
        let salt = salt.unwrap_or(&[0u8; 32]);
        let (prk, _) = hkdf::Hkdf::<Sha256>::extract(Some(salt), secret);
        Box::new(HkdfSha256Expander {
            prk,
        })
    }

    fn expander_for_okm(&self, okm: &OkmBlock) -> Box<dyn HkdfExpander> {
        // Use the OKM directly as the PRK. OkmBlock must be exactly hash-length (32 bytes
        // for SHA-256) per the rustls API contract; enforce at runtime.
        assert_eq!(
            okm.as_ref().len(),
            32,
            "OkmBlock length mismatch: expected 32 bytes for SHA-256, got {}",
            okm.as_ref().len()
        );
        let mut prk = [0u8; 32];
        prk.copy_from_slice(okm.as_ref());
        Box::new(HkdfSha256Expander {
            prk: hkdf::hmac::digest::Output::<Sha256>::from(prk),
        })
    }

    fn hmac_sign(&self, key: &OkmBlock, message: &[u8]) -> Tag {
        let mut mac =
            SimpleHmac::<Sha256>::new_from_slice(key.as_ref()).expect("HMAC key should be valid");
        mac.update(message);
        Tag::new(&mac.finalize().into_bytes()[..])
    }

    fn fips(&self) -> bool {
        false // RustCrypto is not FIPS certified
    }
}

struct HkdfSha256Expander {
    prk: hkdf::hmac::digest::Output<Sha256>,
}

impl HkdfExpander for HkdfSha256Expander {
    fn expand_slice(&self, info: &[&[u8]], output: &mut [u8]) -> Result<(), OutputLengthError> {
        let hkdf = hkdf::Hkdf::<Sha256>::from_prk(&self.prk).map_err(|_| OutputLengthError)?;
        let info_concat: Vec<u8> = info.iter().flat_map(|s| s.iter().copied()).collect();
        hkdf.expand(&info_concat, output).map_err(|_| OutputLengthError)
    }

    fn expand_block(&self, info: &[&[u8]]) -> OkmBlock {
        let mut output = [0u8; 32];
        self.expand_slice(info, &mut output)
            .expect("HKDF expand_block should not fail for hash_len output");
        OkmBlock::new(&output)
    }

    fn hash_len(&self) -> usize {
        32
    }
}

/// HKDF-SHA384 for TLS 1.3.
#[derive(Debug)]
pub struct HkdfSha384;

impl Hkdf for HkdfSha384 {
    fn extract_from_zero_ikm(&self, salt: Option<&[u8]>) -> Box<dyn HkdfExpander> {
        let salt = salt.unwrap_or(&[0u8; 48]);
        let (prk, _) = hkdf::Hkdf::<Sha384>::extract(Some(salt), &[0u8; 48]);
        Box::new(HkdfSha384Expander {
            prk,
        })
    }

    fn extract_from_secret(&self, salt: Option<&[u8]>, secret: &[u8]) -> Box<dyn HkdfExpander> {
        let salt = salt.unwrap_or(&[0u8; 48]);
        let (prk, _) = hkdf::Hkdf::<Sha384>::extract(Some(salt), secret);
        Box::new(HkdfSha384Expander {
            prk,
        })
    }

    fn expander_for_okm(&self, okm: &OkmBlock) -> Box<dyn HkdfExpander> {
        // OkmBlock must be exactly hash-length (48 bytes for SHA-384) per the
        // rustls API contract; enforce at runtime.
        assert_eq!(
            okm.as_ref().len(),
            48,
            "OkmBlock length mismatch: expected 48 bytes for SHA-384, got {}",
            okm.as_ref().len()
        );
        let mut prk = [0u8; 48];
        prk.copy_from_slice(okm.as_ref());
        Box::new(HkdfSha384Expander {
            prk: hkdf::hmac::digest::Output::<Sha384>::from(prk),
        })
    }

    fn hmac_sign(&self, key: &OkmBlock, message: &[u8]) -> Tag {
        let mut mac =
            SimpleHmac::<Sha384>::new_from_slice(key.as_ref()).expect("HMAC key should be valid");
        mac.update(message);
        Tag::new(&mac.finalize().into_bytes()[..])
    }

    fn fips(&self) -> bool {
        false
    }
}

struct HkdfSha384Expander {
    prk: hkdf::hmac::digest::Output<Sha384>,
}

impl HkdfExpander for HkdfSha384Expander {
    fn expand_slice(&self, info: &[&[u8]], output: &mut [u8]) -> Result<(), OutputLengthError> {
        let hkdf = hkdf::Hkdf::<Sha384>::from_prk(&self.prk).map_err(|_| OutputLengthError)?;
        let info_concat: Vec<u8> = info.iter().flat_map(|s| s.iter().copied()).collect();
        hkdf.expand(&info_concat, output).map_err(|_| OutputLengthError)
    }

    fn expand_block(&self, info: &[&[u8]]) -> OkmBlock {
        let mut output = [0u8; 48];
        self.expand_slice(info, &mut output)
            .expect("HKDF expand_block should not fail for hash_len output");
        OkmBlock::new(&output)
    }

    fn hash_len(&self) -> usize {
        48
    }
}

// ============================================================================
// TLS 1.2 PRF Implementations
// ============================================================================

/// TLS 1.2 PRF using SHA-256.
#[derive(Debug)]
pub struct PrfSha256;

impl Prf for PrfSha256 {
    fn for_key_exchange(
        &self,
        output: &mut [u8; 48],
        kx: Box<dyn rustls::crypto::ActiveKeyExchange>,
        peer_pub_key: &[u8],
        label: &[u8],
        seed: &[u8],
    ) -> Result<(), rustls::Error> {
        let shared = kx.complete(peer_pub_key)?;
        self.for_secret(output, shared.secret_bytes(), label, seed);
        Ok(())
    }

    fn for_secret(&self, output: &mut [u8], secret: &[u8], label: &[u8], seed: &[u8]) {
        prf_sha256(output, secret, label, seed);
    }

    fn fips(&self) -> bool {
        false
    }
}

/// TLS 1.2 PRF using SHA-384.
#[derive(Debug)]
pub struct PrfSha384;

impl Prf for PrfSha384 {
    fn for_key_exchange(
        &self,
        output: &mut [u8; 48],
        kx: Box<dyn rustls::crypto::ActiveKeyExchange>,
        peer_pub_key: &[u8],
        label: &[u8],
        seed: &[u8],
    ) -> Result<(), rustls::Error> {
        let shared = kx.complete(peer_pub_key)?;
        self.for_secret(output, shared.secret_bytes(), label, seed);
        Ok(())
    }

    fn for_secret(&self, output: &mut [u8], secret: &[u8], label: &[u8], seed: &[u8]) {
        prf_sha384(output, secret, label, seed);
    }

    fn fips(&self) -> bool {
        false
    }
}

/// TLS 1.2 P_SHA256 function (RFC 5246).
fn prf_sha256(output: &mut [u8], secret: &[u8], label: &[u8], seed: &[u8]) {
    // P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
    //                        HMAC_hash(secret, A(2) + seed) +
    //                        HMAC_hash(secret, A(3) + seed) + ...
    // where A(0) = seed, A(i) = HMAC_hash(secret, A(i-1))

    let mut label_seed = Vec::with_capacity(label.len() + seed.len());
    label_seed.extend_from_slice(label);
    label_seed.extend_from_slice(seed);

    let mut a = {
        let mut mac =
            SimpleHmac::<Sha256>::new_from_slice(secret).expect("HMAC key should be valid");
        mac.update(&label_seed);
        mac.finalize().into_bytes()
    };

    let mut offset = 0;
    while offset < output.len() {
        // P_hash = HMAC(secret, A(i) + seed)
        let mut mac =
            SimpleHmac::<Sha256>::new_from_slice(secret).expect("HMAC key should be valid");
        mac.update(&a);
        mac.update(&label_seed);
        let p = mac.finalize().into_bytes();

        let to_copy = (output.len() - offset).min(32);
        output[offset..offset + to_copy].copy_from_slice(&p[..to_copy]);
        offset += to_copy;

        // A(i+1) = HMAC(secret, A(i))
        let mut mac =
            SimpleHmac::<Sha256>::new_from_slice(secret).expect("HMAC key should be valid");
        mac.update(&a);
        a = mac.finalize().into_bytes();
    }
}

/// TLS 1.2 P_SHA384 function.
fn prf_sha384(output: &mut [u8], secret: &[u8], label: &[u8], seed: &[u8]) {
    let mut label_seed = Vec::with_capacity(label.len() + seed.len());
    label_seed.extend_from_slice(label);
    label_seed.extend_from_slice(seed);

    let mut a = {
        let mut mac =
            SimpleHmac::<Sha384>::new_from_slice(secret).expect("HMAC key should be valid");
        mac.update(&label_seed);
        mac.finalize().into_bytes()
    };

    let mut offset = 0;
    while offset < output.len() {
        let mut mac =
            SimpleHmac::<Sha384>::new_from_slice(secret).expect("HMAC key should be valid");
        mac.update(&a);
        mac.update(&label_seed);
        let p = mac.finalize().into_bytes();

        let to_copy = (output.len() - offset).min(48);
        output[offset..offset + to_copy].copy_from_slice(&p[..to_copy]);
        offset += to_copy;

        let mut mac =
            SimpleHmac::<Sha384>::new_from_slice(secret).expect("HMAC key should be valid");
        mac.update(&a);
        a = mac.finalize().into_bytes();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac_sha256() {
        let key = HMAC_SHA256.with_key(b"secret key");
        let tag = key.sign_concat(b"hello", &[], b" world");
        assert_eq!(tag.as_ref().len(), 32);
    }

    #[test]
    fn test_hmac_sha384() {
        let key = HMAC_SHA384.with_key(b"secret key");
        let tag = key.sign_concat(b"hello", &[], b" world");
        assert_eq!(tag.as_ref().len(), 48);
    }

    #[test]
    fn test_hmac_consistency() {
        let key1 = HMAC_SHA256.with_key(b"key");
        let key2 = HMAC_SHA256.with_key(b"key");

        let tag1 = key1.sign_concat(b"message", &[], b"");
        let tag2 = key2.sign_concat(b"message", &[], b"");

        assert_eq!(tag1.as_ref(), tag2.as_ref());
    }

    #[test]
    fn test_hmac_middle_parts() {
        let key = HMAC_SHA256.with_key(b"key");

        // These should produce the same result
        let tag1 = key.sign_concat(b"", &[b"hello", b" ", b"world"], b"");
        let tag2 = key.sign_concat(b"hello world", &[], b"");

        assert_eq!(tag1.as_ref(), tag2.as_ref());
    }

    // ========================================================================
    // HKDF Tests — RFC 5869 Test Vectors
    // ========================================================================

    #[test]
    fn test_hkdf_sha256_extract_expand_rfc5869_case1() {
        // RFC 5869 Test Case 1: Basic test case with SHA-256
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let expected_okm = hex::decode(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        )
        .unwrap();

        let hkdf = HkdfSha256;
        let expander = hkdf.extract_from_secret(Some(&salt), &ikm);

        let mut okm = vec![0u8; 42];
        expander.expand_slice(&[&info], &mut okm).expect("HKDF expand should succeed");

        assert_eq!(okm, expected_okm);
    }

    #[test]
    fn test_hkdf_sha256_extract_expand_rfc5869_case2() {
        // RFC 5869 Test Case 2: Test with SHA-256 and longer inputs/outputs
        let ikm = hex::decode(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
             202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
             404142434445464748494a4b4c4d4e4f",
        )
        .unwrap();
        let salt = hex::decode(
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\
             808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f\
             a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
        )
        .unwrap();
        let info = hex::decode(
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdce\
             cfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebec\
             edeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        )
        .unwrap();
        let expected_okm = hex::decode(
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
             59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
             cc30c58179ec3e87c14c01d5c1f3434f1d87",
        )
        .unwrap();

        let hkdf = HkdfSha256;
        let expander = hkdf.extract_from_secret(Some(&salt), &ikm);

        let mut okm = vec![0u8; 82];
        expander.expand_slice(&[&info], &mut okm).expect("HKDF expand should succeed");

        assert_eq!(okm, expected_okm);
    }

    #[test]
    fn test_hkdf_sha256_extract_expand_rfc5869_case3() {
        // RFC 5869 Test Case 3: Test with SHA-256 and zero-length salt/info
        let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
        let info: &[u8] = &[];
        let expected_okm = hex::decode(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
             9d201395faa4b61a96c8",
        )
        .unwrap();

        let hkdf = HkdfSha256;
        // Pass None for salt (uses default zero salt)
        let expander = hkdf.extract_from_secret(None, &ikm);

        let mut okm = vec![0u8; 42];
        expander.expand_slice(&[info], &mut okm).expect("HKDF expand should succeed");

        assert_eq!(okm, expected_okm);
    }

    #[test]
    fn test_hkdf_sha256_expand_block() {
        // Verify expand_block returns correct hash-length output
        let ikm = b"input key material";
        let hkdf = HkdfSha256;
        let expander = hkdf.extract_from_secret(None, ikm);

        let block = expander.expand_block(&[b"info"]);
        assert_eq!(block.as_ref().len(), 32);

        // expand_block should be consistent
        let block2 = expander.expand_block(&[b"info"]);
        assert_eq!(block.as_ref(), block2.as_ref());
    }

    #[test]
    fn test_hkdf_sha256_zero_ikm() {
        // Test extract_from_zero_ikm (used in TLS 1.3 key schedule)
        let hkdf = HkdfSha256;
        let expander = hkdf.extract_from_zero_ikm(None);

        let block = expander.expand_block(&[b"test label"]);
        assert_eq!(block.as_ref().len(), 32);
    }

    #[test]
    fn test_hkdf_sha384_extract_expand() {
        // Basic test for SHA-384 HKDF
        let ikm = b"input key material for sha384";
        let salt = b"salt384";
        let info = b"info384";

        let hkdf = HkdfSha384;
        let expander = hkdf.extract_from_secret(Some(salt), ikm);

        let mut okm = vec![0u8; 48];
        expander
            .expand_slice(&[info.as_ref()], &mut okm)
            .expect("HKDF-SHA384 expand should succeed");

        // Output should be non-zero
        assert_ne!(okm, vec![0u8; 48]);

        // Should be consistent
        let mut okm2 = vec![0u8; 48];
        expander
            .expand_slice(&[info.as_ref()], &mut okm2)
            .expect("HKDF-SHA384 expand should succeed");
        assert_eq!(okm, okm2);
    }
}
