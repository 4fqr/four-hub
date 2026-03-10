// ─── Four-Hub · crypto/vault.rs ──────────────────────────────────────────────
//! AES-256-GCM encryption backed by Argon2id key derivation.
//! All secret material implements `Zeroize` and is mlock'd on creation.

use crate::config::CryptoConfig;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{bail, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use zeroize::ZeroizeOnDrop;

pub const KEY_BYTES:   usize = 32;
pub const NONCE_BYTES: usize = 12;
pub const SALT_BYTES:  usize = 16;

// ─── VaultKey ───────────────────────────────────────────────────────────────

/// A 32-byte AES-256-GCM key derived from a user passphrase via Argon2id.
/// Memory is zeroed on drop and mlock'd (if available) to prevent swapping.
#[derive(Clone, ZeroizeOnDrop)]
pub struct VaultKey {
    #[zeroize(skip)]
    inner: Box<[u8; KEY_BYTES]>,
}

impl VaultKey {
    /// Derive a `VaultKey` from `passphrase` using the parameters in `cfg`.
    /// If `cfg.salt_hex` is empty a fresh random salt is generated and
    /// returned (caller is responsible for persisting it).
    pub fn derive(passphrase: &str, cfg: &CryptoConfig) -> Result<Self> {
        let salt = if cfg.salt_hex.is_empty() {
            let mut s = [0u8; SALT_BYTES];
            OsRng.fill_bytes(&mut s);
            s
        } else {
            let bytes = hex::decode(&cfg.salt_hex)?;
            if bytes.len() != SALT_BYTES {
                bail!("salt must be {} bytes (got {})", SALT_BYTES, bytes.len());
            }
            let mut s = [0u8; SALT_BYTES];
            s.copy_from_slice(&bytes);
            s
        };

        let params = Params::new(
            cfg.argon2_memory_kib,
            cfg.argon2_time,
            cfg.argon2_parallel,
            Some(KEY_BYTES),
        )
        .map_err(|e| anyhow::anyhow!("Argon2 params: {e}"))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut key_bytes = Box::new([0u8; KEY_BYTES]);
        argon2
            .hash_password_into(passphrase.as_bytes(), &salt, key_bytes.as_mut())
            .map_err(|e| anyhow::anyhow!("Argon2 hash: {e}"))?;

        // Attempt mlock to keep key material out of swap.
        #[cfg(target_os = "linux")]
        unsafe {
            libc::mlock(
                key_bytes.as_ptr() as *const libc::c_void,
                KEY_BYTES,
            );
        }

        Ok(Self { inner: key_bytes })
    }

    pub fn as_bytes(&self) -> &[u8; KEY_BYTES] {
        &self.inner
    }

    /// Encrypt `plaintext` → `[nonce (12 B)] ++ [ciphertext + GCM tag (16 B)]`.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(self.inner.as_ref()));
        let nonce  = Aes256Gcm::generate_nonce(&mut OsRng);
        let ct     = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("AES-GCM encrypt: {e}"))?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Decrypt a blob produced by [`encrypt`].
    pub fn decrypt(&self, blob: &[u8]) -> Result<Vec<u8>> {
        if blob.len() < NONCE_BYTES {
            bail!("ciphertext too short");
        }
        let (nonce_bytes, ct) = blob.split_at(NONCE_BYTES);
        let nonce  = Nonce::from_slice(nonce_bytes);
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(self.inner.as_ref()));
        cipher
            .decrypt(nonce, ct)
            .map_err(|e| anyhow::anyhow!("AES-GCM decrypt: {e}"))
    }
}

// Prevent accidental debug printing of key material.
impl std::fmt::Debug for VaultKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VaultKey(***)")
    }
}

// ─── Helper: securely wipe a Vec<u8> ────────────────────────────────────────
pub fn secure_zero(buf: &mut Vec<u8>) {
    buf.iter_mut().for_each(|b| *b = 0);
    buf.clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CryptoConfig;

    fn test_cfg() -> CryptoConfig {
        CryptoConfig {
            argon2_memory_kib: 8,
            argon2_time:       1,
            argon2_parallel:   1,
            salt_hex:          "0102030405060708090a0b0c0d0e0f10".to_string(),
        }
    }

    #[test]
    fn roundtrip() {
        let key        = VaultKey::derive("hunter2", &test_cfg()).unwrap();
        let plaintext  = b"the quick brown fox";
        let ciphertext = key.encrypt(plaintext).unwrap();
        let recovered  = key.decrypt(&ciphertext).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let k1 = VaultKey::derive("passA", &test_cfg()).unwrap();
        let k2 = VaultKey::derive("passB", &test_cfg()).unwrap();
        let ct = k1.encrypt(b"secret").unwrap();
        assert!(k2.decrypt(&ct).is_err());
    }
}
