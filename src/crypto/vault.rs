use crate::config::CryptoConfig;
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key as AesKey, Nonce as AesNonce,
};
use chacha20poly1305::{
    ChaCha20Poly1305, Key as ChachaKey, Nonce as ChaChaNonce,
};
use anyhow::{bail, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::ZeroizeOnDrop;

pub const KEY_BYTES:   usize = 32;
pub const NONCE_BYTES: usize = 12;
pub const SALT_BYTES:  usize = 32;

const HKDF_INFO_AES:    &[u8] = b"four-hub-aes-gcm-v1";
const HKDF_INFO_CHACHA: &[u8] = b"four-hub-chacha20-v1";

const MAGIC: &[u8; 4] = b"FH02";

#[derive(ZeroizeOnDrop)]
pub struct VaultKey {
    aes_key:    Box<[u8; KEY_BYTES]>,
    chacha_key: Box<[u8; KEY_BYTES]>,
}

impl Clone for VaultKey {
    fn clone(&self) -> Self {
        let mut a = Box::new([0u8; KEY_BYTES]);
        let mut c = Box::new([0u8; KEY_BYTES]);
        a.copy_from_slice(self.aes_key.as_ref());
        c.copy_from_slice(self.chacha_key.as_ref());
        Self { aes_key: a, chacha_key: c }
    }
}

impl VaultKey {
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
            Some(64),
        ).map_err(|e| anyhow::anyhow!("Argon2 params: {e}"))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut master = [0u8; 64];

        #[cfg(target_os = "linux")]
        unsafe { libc::mlock(master.as_ptr() as *const libc::c_void, 64); }

        argon2.hash_password_into(passphrase.as_bytes(), &salt, &mut master)
            .map_err(|e| anyhow::anyhow!("Argon2 hash: {e}"))?;

        let hk = Hkdf::<Sha256>::new(Some(&salt), &master);

        let mut aes_key = Box::new([0u8; KEY_BYTES]);
        let mut chacha_key = Box::new([0u8; KEY_BYTES]);

        hk.expand(HKDF_INFO_AES, aes_key.as_mut())
            .map_err(|_| anyhow::anyhow!("HKDF expand AES"))?;
        hk.expand(HKDF_INFO_CHACHA, chacha_key.as_mut())
            .map_err(|_| anyhow::anyhow!("HKDF expand ChaCha"))?;

        #[cfg(target_os = "linux")]
        unsafe {
            libc::mlock(aes_key.as_ptr() as *const libc::c_void, KEY_BYTES);
            libc::mlock(chacha_key.as_ptr() as *const libc::c_void, KEY_BYTES);
        }

        volatile_zero(&mut master);

        #[cfg(target_os = "linux")]
        unsafe { libc::munlock(master.as_ptr() as *const libc::c_void, 64); }

        Ok(Self { aes_key, chacha_key })
    }

    pub fn as_bytes(&self) -> &[u8; KEY_BYTES] {
        &self.aes_key
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let aes_cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(self.aes_key.as_ref()));
        let aes_nonce  = Aes256Gcm::generate_nonce(&mut OsRng);
        let ct1 = aes_cipher.encrypt(&aes_nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("AES-GCM encrypt: {e}"))?;

        let cha_cipher = ChaCha20Poly1305::new(ChachaKey::from_slice(self.chacha_key.as_ref()));
        let mut cha_nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut cha_nonce_bytes);
        let cha_nonce = ChaChaNonce::from_slice(&cha_nonce_bytes);
        let ct2 = cha_cipher.encrypt(cha_nonce, ct1.as_ref())
            .map_err(|e| anyhow::anyhow!("ChaCha20-Poly1305 encrypt: {e}"))?;

        let mut out = Vec::with_capacity(4 + 12 + 12 + ct2.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(aes_nonce.as_slice());
        out.extend_from_slice(&cha_nonce_bytes);
        out.extend_from_slice(&ct2);
        Ok(out)
    }

    pub fn decrypt(&self, blob: &[u8]) -> Result<Vec<u8>> {
        if blob.len() < 4 + 12 + 12 {
            bail!("ciphertext too short");
        }
        let (magic, rest)         = blob.split_at(4);
        let (aes_nonce_b, rest)   = rest.split_at(12);
        let (cha_nonce_b, ct2)    = rest.split_at(12);

        if magic != MAGIC {
            bail!("invalid ciphertext magic (version mismatch)");
        }

        let cha_cipher = ChaCha20Poly1305::new(ChachaKey::from_slice(self.chacha_key.as_ref()));
        let cha_nonce  = ChaChaNonce::from_slice(cha_nonce_b);
        let ct1 = cha_cipher.decrypt(cha_nonce, ct2)
            .map_err(|e| anyhow::anyhow!("ChaCha20-Poly1305 decrypt: {e}"))?;

        let aes_cipher = Aes256Gcm::new(AesKey::<Aes256Gcm>::from_slice(self.aes_key.as_ref()));
        let aes_nonce  = AesNonce::from_slice(aes_nonce_b);
        aes_cipher.decrypt(aes_nonce, ct1.as_ref())
            .map_err(|e| anyhow::anyhow!("AES-GCM decrypt: {e}"))
    }
}

impl std::fmt::Debug for VaultKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VaultKey(***)")
    }
}

pub fn secure_zero(buf: &mut Vec<u8>) {
    buf.iter_mut().for_each(|b| unsafe { std::ptr::write_volatile(b, 0u8) });
    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
    buf.clear();
}

fn volatile_zero(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe { std::ptr::write_volatile(b, 0u8); }
    }
    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
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
            salt_hex: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20".to_string(),
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

    #[test]
    fn magic_check_fails_on_bad_data() {
        let key = VaultKey::derive("test", &test_cfg()).unwrap();
        assert!(key.decrypt(b"XXXX000000000000000000000000").is_err());
    }
}
