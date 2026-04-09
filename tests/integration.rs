//! Integration tests for CrabGraph

use crabgraph::{
    aead::{AesGcm256, ChaCha20Poly1305, CrabAead},
    asym::{Ed25519KeyPair, X25519KeyPair},
    hash::sha256,
    kdf::{argon2_derive, pbkdf2_derive_sha256},
    mac::{hmac_sha256, hmac_sha256_verify},
    CrabResult,
};

#[test]
fn test_full_encryption_workflow() -> CrabResult<()> {
    // Generate key from password
    let password = b"test_password";
    let salt = crabgraph::rand::secure_bytes(16)?;
    let key = pbkdf2_derive_sha256(password, &salt, 10_000, 32)?;

    // Encrypt data
    let cipher = AesGcm256::new(key.as_slice())?;
    let plaintext = b"Integration test data";
    let ciphertext = cipher.encrypt(plaintext, None)?;

    // Decrypt
    let decrypted = cipher.decrypt(&ciphertext, None)?;
    assert_eq!(decrypted, plaintext);

    Ok(())
}

#[test]
fn test_key_exchange_and_encryption() -> CrabResult<()> {
    // Alice and Bob perform key exchange
    let alice = X25519KeyPair::generate()?;
    let bob = X25519KeyPair::generate()?;

    let alice_shared = alice.diffie_hellman(&bob.public_key())?;
    let bob_shared = bob.diffie_hellman(&alice.public_key())?;

    // Verify they have the same shared secret
    assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());

    // Derive encryption keys
    let alice_key = alice_shared.derive_key(b"test_app", 32)?;
    let bob_key = bob_shared.derive_key(b"test_app", 32)?;

    // Alice encrypts a message
    let alice_cipher = ChaCha20Poly1305::new(alice_key.as_slice())?;
    let message = b"Hello Bob!";
    let ciphertext = alice_cipher.encrypt(message, None)?;

    // Bob decrypts it
    let bob_cipher = ChaCha20Poly1305::new(bob_key.as_slice())?;
    let decrypted = bob_cipher.decrypt(&ciphertext, None)?;

    assert_eq!(decrypted, message);

    Ok(())
}

#[test]
fn test_sign_and_encrypt() -> CrabResult<()> {
    // Generate signing keypair
    let signer = Ed25519KeyPair::generate()?;

    // Prepare data
    let data = b"Important document";

    // Sign data
    let signature = signer.sign(data);

    // Derive encryption key
    let password = b"encryption_password";
    let salt = crabgraph::rand::secure_bytes(16)?;
    let key = argon2_derive(password, &salt, 32)?;

    // Encrypt data
    let cipher = AesGcm256::new(key.as_slice())?;
    let ciphertext = cipher.encrypt(data, None)?;

    // Encrypt signature too
    let sig_ciphertext = cipher.encrypt(signature.as_bytes(), None)?;

    // Decrypt
    let decrypted_data = cipher.decrypt(&ciphertext, None)?;
    let decrypted_sig_bytes = cipher.decrypt(&sig_ciphertext, None)?;
    let decrypted_sig = crabgraph::asym::Ed25519Signature::from_bytes(&decrypted_sig_bytes)?;

    // Verify signature
    assert!(signer.verify(&decrypted_data, &decrypted_sig)?);
    assert_eq!(decrypted_data, data);

    Ok(())
}

#[test]
fn test_hmac_with_derived_key() -> CrabResult<()> {
    // Derive HMAC key from password
    let password = b"hmac_password";
    let salt = crabgraph::rand::secure_bytes(16)?;
    let hmac_key = pbkdf2_derive_sha256(password, &salt, 10_000, 32)?;

    // Create message
    let message = b"Message to authenticate";

    // Generate HMAC
    let tag = hmac_sha256(hmac_key.as_slice(), message)?;

    // Verify HMAC
    assert!(hmac_sha256_verify(hmac_key.as_slice(), message, &tag)?);

    // Wrong message should fail
    assert!(!hmac_sha256_verify(hmac_key.as_slice(), b"wrong", &tag)?);

    Ok(())
}

#[test]
fn test_hash_chain() -> CrabResult<()> {
    // Create a simple hash chain
    let mut current = sha256(b"genesis");

    for i in 0..10 {
        let data = format!("block_{}", i);
        let mut combined = current.to_vec();
        combined.extend_from_slice(data.as_bytes());
        current = sha256(&combined);
    }

    // Verify chain
    let mut verify = sha256(b"genesis");
    for i in 0..10 {
        let data = format!("block_{}", i);
        let mut combined = verify.to_vec();
        combined.extend_from_slice(data.as_bytes());
        verify = sha256(&combined);
    }

    assert_eq!(current, verify);

    Ok(())
}

#[test]
fn test_multi_recipient_encryption() -> CrabResult<()> {
    // Simulate encrypting for multiple recipients
    let recipients =
        vec![X25519KeyPair::generate()?, X25519KeyPair::generate()?, X25519KeyPair::generate()?];

    let sender = X25519KeyPair::generate()?;
    let message = b"Broadcast message";

    // Encrypt for each recipient
    for recipient in &recipients {
        let shared = sender.diffie_hellman(&recipient.public_key())?;
        let key = shared.derive_key(b"broadcast", 32)?;

        let cipher = AesGcm256::new(key.as_slice())?;
        let ciphertext = cipher.encrypt(message, None)?;

        // Recipient decrypts
        let recipient_shared = recipient.diffie_hellman(&sender.public_key())?;
        let recipient_key = recipient_shared.derive_key(b"broadcast", 32)?;
        let recipient_cipher = AesGcm256::new(recipient_key.as_slice())?;
        let decrypted = recipient_cipher.decrypt(&ciphertext, None)?;

        assert_eq!(decrypted, message);
    }

    Ok(())
}
