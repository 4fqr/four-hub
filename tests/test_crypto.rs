// ─── Four-Hub · tests/test_crypto.rs ─────────────────────────────────────────
//! Integration tests for the crypto vault.

use four_hub::config::CryptoConfig;
use four_hub::crypto::vault::VaultKey;

fn default_cfg() -> CryptoConfig {
    CryptoConfig {
        argon2_memory_kib: 8192,
        argon2_time:       1,
        argon2_parallel:   1,
        // Must be exactly 16 bytes → 32 hex chars
        salt_hex: "deadbeefdeadbeefdeadbeefdeadbeef".to_owned(),
    }
}

#[test]
fn roundtrip_encrypt_decrypt() {
    let cfg = default_cfg();
    let key = VaultKey::derive("correct-horse-battery-staple", &cfg)
        .expect("derive failed");

    let plaintext = b"TOP SECRET - do not share";
    let blob      = key.encrypt(plaintext).expect("encrypt failed");
    let recovered = key.decrypt(&blob).expect("decrypt failed");

    assert_eq!(recovered.as_slice(), plaintext);
}

#[test]
fn wrong_passphrase_fails_decryption() {
    let cfg   = default_cfg();
    let key_a = VaultKey::derive("passphrase-alpha", &cfg).expect("derive key_a");
    let key_b = VaultKey::derive("passphrase-BETA",  &cfg).expect("derive key_b");

    let blob = key_a.encrypt(b"secret data").expect("encrypt");
    let err  = key_b.decrypt(&blob);
    assert!(err.is_err(), "decryption should fail with wrong key");
}

#[test]
fn different_passphrases_produce_different_keys() {
    let cfg   = default_cfg();
    let key_a = VaultKey::derive("passphrase-one", &cfg).unwrap();
    let key_b = VaultKey::derive("passphrase-two", &cfg).unwrap();

    // Encrypt same plaintext with both keys — ciphertext should differ.
    let ct_a = key_a.encrypt(b"data").unwrap();
    let ct_b = key_b.encrypt(b"data").unwrap();
    assert_ne!(ct_a, ct_b);
}

#[test]
fn encrypt_produces_unique_nonces() {
    let cfg = default_cfg();
    let key = VaultKey::derive("nonce-test", &cfg).unwrap();

    let ct1 = key.encrypt(b"same plaintext").unwrap();
    let ct2 = key.encrypt(b"same plaintext").unwrap();

    // Each call should produce a fresh random nonce → different blobs.
    assert_ne!(ct1, ct2, "nonces must be unique per encryption");
}

#[test]
fn empty_plaintext_roundtrip() {
    let cfg = default_cfg();
    let key = VaultKey::derive("empty-test", &cfg).unwrap();

    let blob = key.encrypt(b"").unwrap();
    let recovered = key.decrypt(&blob).unwrap();
    assert_eq!(recovered.as_slice(), b"");
}
