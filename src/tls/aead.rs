//! AEAD cipher implementations for TLS.
//!
//! This module provides AEAD (Authenticated Encryption with Associated Data)
//! implementations for TLS 1.2 and TLS 1.3:
//! - AES-128-GCM
//! - AES-256-GCM
//! - ChaCha20-Poly1305

use aes_gcm::aead;
use rustls::crypto::cipher::{
    make_tls12_aad, make_tls13_aad, AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv,
    KeyBlockShape, MessageDecrypter, MessageEncrypter, Nonce, OutboundOpaqueMessage,
    OutboundPlainMessage, PrefixedPayload, Tls12AeadAlgorithm, Tls13AeadAlgorithm,
    UnsupportedOperationError,
};
use rustls::{ConnectionTrafficSecrets, ContentType};

use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;

/// AES-128-GCM AEAD algorithm for TLS 1.3.
pub static AES_128_GCM: Aes128GcmAead = Aes128GcmAead;

/// AES-256-GCM AEAD algorithm for TLS 1.3.
pub static AES_256_GCM: Aes256GcmAead = Aes256GcmAead;

/// ChaCha20-Poly1305 AEAD algorithm for TLS 1.3.
pub static CHACHA20_POLY1305: ChaCha20Poly1305Aead = ChaCha20Poly1305Aead;

/// AES-128-GCM AEAD algorithm for TLS 1.2.
pub static AES_128_GCM_TLS12: Aes128GcmTls12Aead = Aes128GcmTls12Aead;

/// AES-256-GCM AEAD algorithm for TLS 1.2.
pub static AES_256_GCM_TLS12: Aes256GcmTls12Aead = Aes256GcmTls12Aead;

/// ChaCha20-Poly1305 AEAD algorithm for TLS 1.2.
pub static CHACHA20_POLY1305_TLS12: ChaCha20Poly1305Tls12Aead = ChaCha20Poly1305Tls12Aead;

// Tag length for all our AEAD algorithms
const TAG_LEN: usize = 16;

// Explicit nonce length for TLS 1.2 GCM
const TLS12_GCM_EXPLICIT_NONCE_LEN: usize = 8;
const TLS12_GCM_OVERHEAD: usize = TLS12_GCM_EXPLICIT_NONCE_LEN + TAG_LEN;

// ============================================================================
// Buffer adapter for in-place encryption
// ============================================================================

/// Adapter to allow in-place encryption with PrefixedPayload
struct EncryptBufferAdapter<'a>(&'a mut PrefixedPayload);

impl aead::Buffer for EncryptBufferAdapter<'_> {
    fn extend_from_slice(&mut self, other: &[u8]) -> aead::Result<()> {
        self.0.extend_from_slice(other);
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        self.0.truncate(len);
    }

    fn len(&self) -> usize {
        self.0.as_ref().len()
    }

    fn is_empty(&self) -> bool {
        self.0.as_ref().is_empty()
    }
}

impl AsRef<[u8]> for EncryptBufferAdapter<'_> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsMut<[u8]> for EncryptBufferAdapter<'_> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

/// Adapter to allow in-place decryption with a mutable byte slice that can shrink
struct DecryptBufferAdapter<'a, 'p>(&'a mut InboundOpaqueMessage<'p>);

impl aead::Buffer for DecryptBufferAdapter<'_, '_> {
    fn extend_from_slice(&mut self, _other: &[u8]) -> aead::Result<()> {
        // Decryption shouldn't extend
        unreachable!("decrypt should not extend buffer");
    }

    fn truncate(&mut self, len: usize) {
        self.0.payload.truncate(len);
    }

    fn len(&self) -> usize {
        self.0.payload.len()
    }

    fn is_empty(&self) -> bool {
        self.0.payload.is_empty()
    }
}

impl AsRef<[u8]> for DecryptBufferAdapter<'_, '_> {
    fn as_ref(&self) -> &[u8] {
        &self.0.payload
    }
}

impl AsMut<[u8]> for DecryptBufferAdapter<'_, '_> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0.payload
    }
}

// ============================================================================
// TLS 1.3 AEAD Algorithms
// ============================================================================

/// AES-128-GCM for TLS 1.3.
#[derive(Debug)]
pub struct Aes128GcmAead;

impl Tls13AeadAlgorithm for Aes128GcmAead {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Tls13Encrypter::<Aes128Gcm> {
            cipher: Aes128Gcm::new_from_slice(key.as_ref()).unwrap(),
            iv,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Tls13Decrypter::<Aes128Gcm> {
            cipher: Aes128Gcm::new_from_slice(key.as_ref()).unwrap(),
            iv,
        })
    }

    fn key_len(&self) -> usize {
        16
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Aes128Gcm {
            key,
            iv,
        })
    }
}

/// AES-256-GCM for TLS 1.3.
#[derive(Debug)]
pub struct Aes256GcmAead;

impl Tls13AeadAlgorithm for Aes256GcmAead {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Tls13Encrypter::<Aes256Gcm> {
            cipher: Aes256Gcm::new_from_slice(key.as_ref()).unwrap(),
            iv,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Tls13Decrypter::<Aes256Gcm> {
            cipher: Aes256Gcm::new_from_slice(key.as_ref()).unwrap(),
            iv,
        })
    }

    fn key_len(&self) -> usize {
        32
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Aes256Gcm {
            key,
            iv,
        })
    }
}

/// ChaCha20-Poly1305 for TLS 1.3.
#[derive(Debug)]
pub struct ChaCha20Poly1305Aead;

impl Tls13AeadAlgorithm for ChaCha20Poly1305Aead {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Tls13ChaChaEncrypter {
            cipher: ChaCha20Poly1305::new_from_slice(key.as_ref()).unwrap(),
            iv,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Tls13ChaChaDecrypter {
            cipher: ChaCha20Poly1305::new_from_slice(key.as_ref()).unwrap(),
            iv,
        })
    }

    fn key_len(&self) -> usize {
        32
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 {
            key,
            iv,
        })
    }
}

// ============================================================================
// TLS 1.2 AEAD Algorithms
// ============================================================================

/// AES-128-GCM for TLS 1.2.
#[derive(Debug)]
pub struct Aes128GcmTls12Aead;

impl Tls12AeadAlgorithm for Aes128GcmTls12Aead {
    fn encrypter(
        &self,
        key: AeadKey,
        write_iv: &[u8],
        explicit: &[u8],
    ) -> Box<dyn MessageEncrypter> {
        Box::new(Tls12GcmEncrypter::<Aes128Gcm> {
            cipher: Aes128Gcm::new_from_slice(key.as_ref()).unwrap(),
            full_iv: build_tls12_iv(write_iv, explicit),
        })
    }

    fn decrypter(&self, key: AeadKey, write_iv: &[u8]) -> Box<dyn MessageDecrypter> {
        Box::new(Tls12GcmDecrypter::<Aes128Gcm> {
            cipher: Aes128Gcm::new_from_slice(key.as_ref()).unwrap(),
            implicit_iv: write_iv.try_into().expect("TLS 1.2 GCM implicit IV must be 4 bytes"),
        })
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: 16,
            fixed_iv_len: 4,
            explicit_nonce_len: 8,
        }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        // TLS 1.2 GCM uses 4-byte fixed IV + 8-byte explicit nonce = 12-byte nonce
        if iv.len() != 4 || explicit.len() != 8 {
            return Err(UnsupportedOperationError);
        }
        let mut full_iv = [0u8; 12];
        full_iv[..4].copy_from_slice(iv);
        full_iv[4..].copy_from_slice(explicit);
        Ok(ConnectionTrafficSecrets::Aes128Gcm {
            key,
            iv: Iv::new(full_iv),
        })
    }
}

/// AES-256-GCM for TLS 1.2.
#[derive(Debug)]
pub struct Aes256GcmTls12Aead;

impl Tls12AeadAlgorithm for Aes256GcmTls12Aead {
    fn encrypter(
        &self,
        key: AeadKey,
        write_iv: &[u8],
        explicit: &[u8],
    ) -> Box<dyn MessageEncrypter> {
        Box::new(Tls12GcmEncrypter::<Aes256Gcm> {
            cipher: Aes256Gcm::new_from_slice(key.as_ref()).unwrap(),
            full_iv: build_tls12_iv(write_iv, explicit),
        })
    }

    fn decrypter(&self, key: AeadKey, write_iv: &[u8]) -> Box<dyn MessageDecrypter> {
        Box::new(Tls12GcmDecrypter::<Aes256Gcm> {
            cipher: Aes256Gcm::new_from_slice(key.as_ref()).unwrap(),
            implicit_iv: write_iv.try_into().expect("TLS 1.2 GCM implicit IV must be 4 bytes"),
        })
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: 32,
            fixed_iv_len: 4,
            explicit_nonce_len: 8,
        }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        // TLS 1.2 GCM uses 4-byte fixed IV + 8-byte explicit nonce = 12-byte nonce
        if iv.len() != 4 || explicit.len() != 8 {
            return Err(UnsupportedOperationError);
        }
        let mut full_iv = [0u8; 12];
        full_iv[..4].copy_from_slice(iv);
        full_iv[4..].copy_from_slice(explicit);
        Ok(ConnectionTrafficSecrets::Aes256Gcm {
            key,
            iv: Iv::new(full_iv),
        })
    }
}

/// ChaCha20-Poly1305 for TLS 1.2.
#[derive(Debug)]
pub struct ChaCha20Poly1305Tls12Aead;

impl Tls12AeadAlgorithm for ChaCha20Poly1305Tls12Aead {
    fn encrypter(
        &self,
        key: AeadKey,
        write_iv: &[u8],
        _explicit: &[u8],
    ) -> Box<dyn MessageEncrypter> {
        Box::new(Tls12ChaChaEncrypter {
            cipher: ChaCha20Poly1305::new_from_slice(key.as_ref()).unwrap(),
            iv: Iv::copy(write_iv),
        })
    }

    fn decrypter(&self, key: AeadKey, write_iv: &[u8]) -> Box<dyn MessageDecrypter> {
        Box::new(Tls12ChaChaDecrypter {
            cipher: ChaCha20Poly1305::new_from_slice(key.as_ref()).unwrap(),
            iv: Iv::copy(write_iv),
        })
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: 32,
            fixed_iv_len: 12,
            explicit_nonce_len: 0,
        }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        _explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 {
            key,
            iv: Iv::new(iv[..].try_into().unwrap()),
        })
    }
}

// ============================================================================
// TLS 1.3 Encrypter/Decrypter for AES-GCM
// ============================================================================

struct Tls13Encrypter<C: AeadInPlace + Send + Sync> {
    cipher: C,
    iv: Iv,
}

impl<C: AeadInPlace + Send + Sync> MessageEncrypter for Tls13Encrypter<C> {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, rustls::Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);

        // Copy plaintext using extend_from_chunks for OutboundChunks
        payload.extend_from_chunks(&msg.payload);
        // Append content type (TLS 1.3 puts it inside the encrypted payload)
        payload.extend_from_slice(&msg.typ.to_array());

        // Create nonce by XORing IV with sequence number
        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls13_aad(total_len);

        // Encrypt in-place using buffer adapter
        self.cipher
            .encrypt_in_place(
                aes_gcm::Nonce::from_slice(&nonce.0),
                &aad,
                &mut EncryptBufferAdapter(&mut payload),
            )
            .map_err(|_| rustls::Error::EncryptError)?;

        Ok(OutboundOpaqueMessage::new(ContentType::ApplicationData, msg.version, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + TAG_LEN // payload + content type + tag
    }
}

struct Tls13Decrypter<C: AeadInPlace + Send + Sync> {
    cipher: C,
    iv: Iv,
}

impl<C: AeadInPlace + Send + Sync> MessageDecrypter for Tls13Decrypter<C> {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, rustls::Error> {
        let payload_len = msg.payload.len();
        if payload_len < TAG_LEN + 1 {
            return Err(rustls::Error::DecryptError);
        }

        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls13_aad(payload_len);

        // Decrypt in-place
        self.cipher
            .decrypt_in_place(
                aes_gcm::Nonce::from_slice(&nonce.0),
                &aad,
                &mut DecryptBufferAdapter(&mut msg),
            )
            .map_err(|_| rustls::Error::DecryptError)?;

        // Parse TLS 1.3 inner content type
        msg.into_tls13_unpadded_message()
    }
}

// ============================================================================
// TLS 1.3 ChaCha20-Poly1305 Encrypter/Decrypter
// ============================================================================

struct Tls13ChaChaEncrypter {
    cipher: ChaCha20Poly1305,
    iv: Iv,
}

impl MessageEncrypter for Tls13ChaChaEncrypter {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, rustls::Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);

        payload.extend_from_chunks(&msg.payload);
        payload.extend_from_slice(&msg.typ.to_array());

        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls13_aad(total_len);

        self.cipher
            .encrypt_in_place(
                chacha20poly1305::Nonce::from_slice(&nonce.0),
                &aad,
                &mut EncryptBufferAdapter(&mut payload),
            )
            .map_err(|_| rustls::Error::EncryptError)?;

        Ok(OutboundOpaqueMessage::new(ContentType::ApplicationData, msg.version, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + TAG_LEN
    }
}

struct Tls13ChaChaDecrypter {
    cipher: ChaCha20Poly1305,
    iv: Iv,
}

impl MessageDecrypter for Tls13ChaChaDecrypter {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, rustls::Error> {
        let payload_len = msg.payload.len();
        if payload_len < TAG_LEN + 1 {
            return Err(rustls::Error::DecryptError);
        }

        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls13_aad(payload_len);

        self.cipher
            .decrypt_in_place(
                chacha20poly1305::Nonce::from_slice(&nonce.0),
                &aad,
                &mut DecryptBufferAdapter(&mut msg),
            )
            .map_err(|_| rustls::Error::DecryptError)?;

        msg.into_tls13_unpadded_message()
    }
}

// ============================================================================
// TLS 1.2 GCM Encrypter/Decrypter
// ============================================================================

struct Tls12GcmEncrypter<C: AeadInPlace + Send + Sync> {
    cipher: C,
    full_iv: [u8; 12],
}

impl<C: AeadInPlace + Send + Sync> MessageEncrypter for Tls12GcmEncrypter<C> {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, rustls::Error> {
        let payload_len = msg.payload.len();
        let total_len = self.encrypted_payload_len(payload_len);
        let mut payload = PrefixedPayload::with_capacity(total_len);

        // Build the nonce: implicit (4 bytes) || explicit (8 bytes from seq)
        let mut nonce = self.full_iv;
        let seq_bytes = seq.to_be_bytes();
        nonce[4..12].copy_from_slice(&seq_bytes);

        // Prepend explicit nonce to payload
        payload.extend_from_slice(&seq_bytes);
        // Add plaintext
        payload.extend_from_chunks(&msg.payload);

        // Create AAD for TLS 1.2
        let aad = make_tls12_aad(seq, msg.typ, msg.version, payload_len);

        // Encrypt only the plaintext portion (skip the explicit nonce prefix)
        let plaintext_start = TLS12_GCM_EXPLICIT_NONCE_LEN;
        let plaintext_end = TLS12_GCM_EXPLICIT_NONCE_LEN + payload_len;

        // We need to encrypt in place but only on a portion
        // Create a temporary buffer for encryption
        let data = payload.as_mut();
        let to_encrypt = &mut data[plaintext_start..plaintext_end];
        let mut temp = to_encrypt.to_vec();

        self.cipher
            .encrypt_in_place(aes_gcm::Nonce::from_slice(&nonce), &aad, &mut temp)
            .map_err(|_| rustls::Error::EncryptError)?;

        // Copy encrypted data back (plaintext_len + TAG_LEN)
        data[plaintext_start..plaintext_start + temp.len()].copy_from_slice(&temp);

        // Update payload length to include tag
        // The tag was appended to temp by encrypt_in_place

        Ok(OutboundOpaqueMessage::new(msg.typ, msg.version, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        TLS12_GCM_EXPLICIT_NONCE_LEN + payload_len + TAG_LEN
    }
}

struct Tls12GcmDecrypter<C: AeadInPlace + Send + Sync> {
    cipher: C,
    implicit_iv: [u8; 4],
}

impl<C: AeadInPlace + Send + Sync> MessageDecrypter for Tls12GcmDecrypter<C> {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, rustls::Error> {
        let payload_len = msg.payload.len();
        if payload_len < TLS12_GCM_OVERHEAD {
            return Err(rustls::Error::DecryptError);
        }

        // Build nonce from implicit IV + explicit nonce from message
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.implicit_iv);
        nonce[4..12].copy_from_slice(&msg.payload[..8]);

        // Calculate plaintext length
        let plaintext_len = payload_len - TLS12_GCM_OVERHEAD;
        let aad = make_tls12_aad(seq, msg.typ, msg.version, plaintext_len);

        // For TLS 1.2 GCM, we need to decrypt in-place with offset handling.
        // Copy the payload (after explicit nonce) to a temp buffer.
        let ciphertext_with_tag = &msg.payload[TLS12_GCM_EXPLICIT_NONCE_LEN..];
        let mut temp = ciphertext_with_tag.to_vec();

        self.cipher
            .decrypt_in_place(aes_gcm::Nonce::from_slice(&nonce), &aad, &mut temp)
            .map_err(|_| rustls::Error::DecryptError)?;

        // Copy decrypted plaintext back to the beginning of payload
        msg.payload[..temp.len()].copy_from_slice(&temp);
        msg.payload.truncate(temp.len());

        Ok(msg.into_plain_message())
    }
}

// ============================================================================
// TLS 1.2 ChaCha20-Poly1305 (different nonce construction)
// ============================================================================

struct Tls12ChaChaEncrypter {
    cipher: ChaCha20Poly1305,
    iv: Iv,
}

impl MessageEncrypter for Tls12ChaChaEncrypter {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, rustls::Error> {
        let payload_len = msg.payload.len();
        let total_len = self.encrypted_payload_len(payload_len);
        let mut payload = PrefixedPayload::with_capacity(total_len);
        payload.extend_from_chunks(&msg.payload);

        // ChaCha20-Poly1305 in TLS 1.2: XOR IV with padded seq number
        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls12_aad(seq, msg.typ, msg.version, payload_len);

        self.cipher
            .encrypt_in_place(
                chacha20poly1305::Nonce::from_slice(&nonce.0),
                &aad,
                &mut EncryptBufferAdapter(&mut payload),
            )
            .map_err(|_| rustls::Error::EncryptError)?;

        Ok(OutboundOpaqueMessage::new(msg.typ, msg.version, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + TAG_LEN
    }
}

struct Tls12ChaChaDecrypter {
    cipher: ChaCha20Poly1305,
    iv: Iv,
}

impl MessageDecrypter for Tls12ChaChaDecrypter {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, rustls::Error> {
        let payload_len = msg.payload.len();
        if payload_len < TAG_LEN {
            return Err(rustls::Error::DecryptError);
        }

        let plaintext_len = payload_len - TAG_LEN;
        let nonce = Nonce::new(&self.iv, seq);
        let aad = make_tls12_aad(seq, msg.typ, msg.version, plaintext_len);

        self.cipher
            .decrypt_in_place(
                chacha20poly1305::Nonce::from_slice(&nonce.0),
                &aad,
                &mut DecryptBufferAdapter(&mut msg),
            )
            .map_err(|_| rustls::Error::DecryptError)?;

        Ok(msg.into_plain_message())
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

fn build_tls12_iv(implicit: &[u8], explicit: &[u8]) -> [u8; 12] {
    // TLS 1.2 GCM nonce = 4-byte implicit (fixed) IV || 8-byte explicit nonce.
    // Hard runtime check: invalid lengths indicate a serious internal bug.
    assert_eq!(implicit.len(), 4, "TLS 1.2 implicit IV must be 4 bytes");
    assert_eq!(explicit.len(), 8, "TLS 1.2 explicit nonce must be 8 bytes");
    let mut full = [0u8; 12];
    full[..4].copy_from_slice(implicit);
    full[4..12].copy_from_slice(explicit);
    full
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_128_gcm_key_len() {
        assert_eq!(AES_128_GCM.key_len(), 16);
    }

    #[test]
    fn test_aes_256_gcm_key_len() {
        assert_eq!(AES_256_GCM.key_len(), 32);
    }

    #[test]
    fn test_chacha20_poly1305_key_len() {
        assert_eq!(CHACHA20_POLY1305.key_len(), 32);
    }

    #[test]
    fn test_tls12_aes_128_key_block_shape() {
        let shape = AES_128_GCM_TLS12.key_block_shape();
        assert_eq!(shape.enc_key_len, 16);
        assert_eq!(shape.fixed_iv_len, 4);
        assert_eq!(shape.explicit_nonce_len, 8);
    }

    #[test]
    fn test_tls12_aes_256_key_block_shape() {
        let shape = AES_256_GCM_TLS12.key_block_shape();
        assert_eq!(shape.enc_key_len, 32);
        assert_eq!(shape.fixed_iv_len, 4);
        assert_eq!(shape.explicit_nonce_len, 8);
    }

    #[test]
    fn test_tls12_chacha_key_block_shape() {
        let shape = CHACHA20_POLY1305_TLS12.key_block_shape();
        assert_eq!(shape.enc_key_len, 32);
        assert_eq!(shape.fixed_iv_len, 12);
        assert_eq!(shape.explicit_nonce_len, 0);
    }

    #[test]
    fn test_build_tls12_iv() {
        let implicit = [0x01, 0x02, 0x03, 0x04];
        let explicit = [0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c];
        let full = build_tls12_iv(&implicit, &explicit);
        assert_eq!(full, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c]);
    }
}
