//! AES Key Wrap (RFC 3394) Example
//!
//! Demonstrates how to use CrabGraph's key wrapping functionality to securely
//! encrypt key material with Key Encryption Keys (KEKs).
//!
//! Run this example with:
//! ```bash
//! cargo run --example key_wrapping_example
//! ```

use crabgraph::{
    kw::{Kw128, Kw192, Kw256},
    CrabResult,
};

/// Demo 1: Basic Key Wrapping with AES-256
///
/// Shows the fundamental wrap/unwrap operation with a 256-bit KEK.
/// This is the recommended key size for most applications.
fn demo_basic_wrapping() -> CrabResult<()> {
    println!("=== Demo 1: Basic Key Wrapping ===\n");

    // Generate a random 256-bit KEK (Key Encryption Key)
    let kek = Kw256::generate_kek()?;
    println!("Generated 256-bit KEK: {} bytes", kek.len());

    // Create wrapper instance
    let wrapper = Kw256::new(&kek)?;

    // Simulate a session key that needs to be stored/transmitted securely
    let session_key = [0x42u8; 32]; // 256-bit AES key
    println!("Session key to wrap: {:02x?}...", &session_key[..8]);

    // Wrap the key (deterministic encryption + integrity protection)
    let wrapped = wrapper.wrap_key(&session_key)?;
    println!("Wrapped key: {} bytes", wrapped.len());
    println!("Wrapped data: {:02x?}...\n", &wrapped[..16]);

    // Later, unwrap to use the key
    let unwrapped = wrapper.unwrap_key(&wrapped)?;
    assert_eq!(unwrapped, session_key);
    println!("✓ Successfully unwrapped key");
    println!("✓ Integrity verified (IV check passed)\n");

    Ok(())
}

/// Demo 2: HSM-Style Key Export/Import Workflow
///
/// Demonstrates a realistic scenario where keys are exported from one system
/// and imported into another using key wrapping.
fn demo_hsm_workflow() -> CrabResult<()> {
    println!("=== Demo 2: HSM Key Export/Import ===\n");

    // System A: Master KEK (would be stored in HSM)
    let master_kek = Kw256::generate_kek()?;
    let exporter = Kw256::new(&master_kek)?;
    println!("System A: Master KEK initialized");

    // System A: Generate and wrap a database encryption key
    let db_key = [0x11u8; 32];
    println!("System A: Database key generated");

    let wrapped_db_key = exporter.wrap_key(&db_key)?;
    println!("System A: Key wrapped for export ({} bytes)", wrapped_db_key.len());
    println!("System A: Wrapped data: {:02x?}...", &wrapped_db_key[..16]);

    // Transmit wrapped_db_key over insecure channel...
    println!("\n[Transmitting wrapped key over network...]");

    // System B: Import the key using shared KEK
    let importer = Kw256::new(&master_kek)?;
    println!("\nSystem B: Master KEK configured");

    let imported_key = importer.unwrap_key(&wrapped_db_key)?;
    println!("System B: Key imported successfully");

    // Verify integrity
    assert_eq!(imported_key, db_key);
    println!("✓ Key matches original");
    println!("✓ No tampering detected\n");

    Ok(())
}

/// Demo 3: Multiple Key Sizes
///
/// Shows usage of different KEK sizes (128, 192, 256 bits).
/// AES-256 is recommended, but other sizes are available for compatibility.
fn demo_multiple_sizes() -> CrabResult<()> {
    println!("=== Demo 3: Multiple Key Sizes ===\n");

    let test_key = [0x33u8; 24]; // 192-bit key to wrap

    // AES-128 Key Wrap
    let kek128 = Kw128::generate_kek()?;
    let wrapper128 = Kw128::new(&kek128)?;
    let wrapped128 = wrapper128.wrap_key(&test_key)?;
    println!("Kw128: Wrapped {} bytes → {} bytes", test_key.len(), wrapped128.len());

    // AES-192 Key Wrap
    let kek192 = Kw192::generate_kek()?;
    let wrapper192 = Kw192::new(&kek192)?;
    let wrapped192 = wrapper192.wrap_key(&test_key)?;
    println!("Kw192: Wrapped {} bytes → {} bytes", test_key.len(), wrapped192.len());

    // AES-256 Key Wrap (Recommended)
    let kek256 = Kw256::generate_kek()?;
    let wrapper256 = Kw256::new(&kek256)?;
    let wrapped256 = wrapper256.wrap_key(&test_key)?;
    println!("Kw256: Wrapped {} bytes → {} bytes (RECOMMENDED)", test_key.len(), wrapped256.len());

    // Verify all unwrap correctly
    assert_eq!(wrapper128.unwrap_key(&wrapped128)?, test_key);
    assert_eq!(wrapper192.unwrap_key(&wrapped192)?, test_key);
    assert_eq!(wrapper256.unwrap_key(&wrapped256)?, test_key);
    println!("\n✓ All sizes work correctly");
    println!("✓ Use Kw256 for maximum security\n");

    Ok(())
}

/// Demo 4: Error Handling
///
/// Shows how key wrapping detects tampering, wrong KEKs, and invalid inputs.
fn demo_error_handling() -> CrabResult<()> {
    println!("=== Demo 4: Error Handling ===\n");

    let kek = Kw256::generate_kek()?;
    let wrapper = Kw256::new(&kek)?;
    let key = [0x55u8; 32];
    let wrapped = wrapper.wrap_key(&key)?;

    // Test 1: Wrong KEK detection
    println!("Test 1: Wrong KEK detection");
    let wrong_kek = Kw256::generate_kek()?;
    let wrong_wrapper = Kw256::new(&wrong_kek)?;
    match wrong_wrapper.unwrap_key(&wrapped) {
        Ok(_) => println!("  ✗ Should have failed!"),
        Err(e) => println!("  ✓ Correctly detected wrong KEK: {}", e),
    }

    // Test 2: Tampered data detection
    println!("\nTest 2: Tampered data detection");
    let mut tampered = wrapped.clone();
    tampered[5] ^= 0xFF; // Flip bits
    match wrapper.unwrap_key(&tampered) {
        Ok(_) => println!("  ✗ Should have detected tampering!"),
        Err(e) => println!("  ✓ Correctly detected tampering: {}", e),
    }

    // Test 3: Invalid input lengths
    println!("\nTest 3: Invalid input lengths");

    // Key too small
    let tiny_key = [0u8; 8];
    match wrapper.wrap_key(&tiny_key) {
        Ok(_) => println!("  ✗ Should reject small key!"),
        Err(e) => println!("  ✓ Rejected key < 16 bytes: {}", e),
    }

    // Key not multiple of 8
    let odd_key = [0u8; 19];
    match wrapper.wrap_key(&odd_key) {
        Ok(_) => println!("  ✗ Should reject non-8-byte-multiple!"),
        Err(e) => println!("  ✓ Rejected non-aligned key: {}", e),
    }

    // Wrong KEK size
    println!("\nTest 4: Invalid KEK size");
    let bad_kek = [0u8; 31]; // Should be 32
    match Kw256::new(&bad_kek) {
        Ok(_) => println!("  ✗ Should reject wrong KEK size!"),
        Err(e) => println!("  ✓ Rejected invalid KEK: {}", e),
    }

    println!("\n✓ All error cases handled correctly\n");

    Ok(())
}

/// Demo 5: Deterministic Encryption Property
///
/// Shows that key wrapping is deterministic (same input = same output).
/// This is by design for key wrapping but differs from AEAD ciphers.
fn demo_deterministic() -> CrabResult<()> {
    println!("=== Demo 5: Deterministic Encryption ===\n");

    let kek = Kw256::generate_kek()?;
    let wrapper = Kw256::new(&kek)?;
    let key = [0x77u8; 32];

    // Wrap the same key twice
    let wrapped1 = wrapper.wrap_key(&key)?;
    let wrapped2 = wrapper.wrap_key(&key)?;

    println!("Wrapped #1: {:02x?}...", &wrapped1[..16]);
    println!("Wrapped #2: {:02x?}...", &wrapped2[..16]);

    if wrapped1 == wrapped2 {
        println!("\n✓ Deterministic: Same input → Same output");
        println!("  This is EXPECTED for key wrapping");
        println!("  (Unlike AEAD which uses random nonces)");
    } else {
        println!("\n✗ Unexpected: Outputs differ!");
    }

    println!("\n⚠️  Security Note:");
    println!("  Key wrapping is deterministic by design (RFC 3394)");
    println!("  Only use for wrapping key material, not arbitrary data");
    println!("  For general encryption, use AEAD ciphers (AES-GCM, ChaCha20-Poly1305)\n");

    Ok(())
}

/// Demo 6: Practical Key Storage
///
/// Shows how to use key wrapping for secure key storage at rest.
fn demo_key_storage() -> CrabResult<()> {
    println!("=== Demo 6: Practical Key Storage ===\n");

    // Master KEK (would be derived from user password or stored in HSM)
    let master_kek = Kw256::generate_kek()?;
    let wrapper = Kw256::new(&master_kek)?;
    println!("Master KEK initialized (32 bytes)");

    // Application generates multiple keys for different purposes
    let encryption_key = [0xAAu8; 32];
    let signing_key = [0xBBu8; 32];
    let backup_key = [0xCCu8; 32];

    // Wrap all keys with the master KEK
    let wrapped_encryption = wrapper.wrap_key(&encryption_key)?;
    let wrapped_signing = wrapper.wrap_key(&signing_key)?;
    let wrapped_backup = wrapper.wrap_key(&backup_key)?;

    println!("Wrapped encryption key: {} bytes", wrapped_encryption.len());
    println!("Wrapped signing key:    {} bytes", wrapped_signing.len());
    println!("Wrapped backup key:     {} bytes", wrapped_backup.len());

    // Store wrapped keys in database/config file
    println!("\n[Storing wrapped keys in database...]");
    println!("  - Only wrapped forms are stored");
    println!("  - Master KEK is never stored with wrapped keys");
    println!("  - Master KEK may be derived from password or in HSM");

    // Later, load and unwrap when needed
    println!("\n[Loading wrapped keys from storage...]");
    let loaded_encryption = wrapper.unwrap_key(&wrapped_encryption)?;
    let loaded_signing = wrapper.unwrap_key(&wrapped_signing)?;
    let loaded_backup = wrapper.unwrap_key(&wrapped_backup)?;

    assert_eq!(loaded_encryption, encryption_key);
    assert_eq!(loaded_signing, signing_key);
    assert_eq!(loaded_backup, backup_key);

    println!("✓ All keys loaded successfully");
    println!("✓ Integrity verified for all keys");
    println!("\n✓ Ready to use unwrapped keys for operations\n");

    Ok(())
}

fn main() -> CrabResult<()> {
    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║         CrabGraph AES Key Wrap (RFC 3394) Examples          ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    demo_basic_wrapping()?;
    demo_hsm_workflow()?;
    demo_multiple_sizes()?;
    demo_error_handling()?;
    demo_deterministic()?;
    demo_key_storage()?;

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║                      Key Takeaways                           ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║ • Use Kw256 (32-byte KEK) for maximum security             ║");
    println!("║ • Key wrapping is deterministic (by design)                 ║");
    println!("║ • Built-in integrity protection detects tampering           ║");
    println!("║ • Only for keys - use AEAD for general data                 ║");
    println!("║ • RFC 3394 compliant implementation                         ║");
    println!("║ • Automatic validation of sizes and alignment               ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    Ok(())
}
