//! Security primitives: AES-256-GCM credential sealing, Argon2id password
//! hashing and opaque session tokens. Secrets are never stored in plaintext and
//! never returned by serializers.

use crate::error::{Error, Result};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const SEALED_PREFIX: &str = "nc1:";

pub struct MasterKey(Zeroizing<[u8; KEY_LEN]>);

impl MasterKey {
    pub fn load_or_create(path: &Path) -> Result<Self> {
        if path.exists() {
            let raw = fs::read_to_string(path)?;
            let decoded = STANDARD
                .decode(raw.trim())
                .map_err(|_| Error::Security("master key is corrupt".into()))?;
            if decoded.len() != KEY_LEN {
                return Err(Error::Security("master key has invalid length".into()));
            }
            let mut key = [0u8; KEY_LEN];
            key.copy_from_slice(&decoded);
            Ok(Self(Zeroizing::new(key)))
        } else {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut key = [0u8; KEY_LEN];
            OsRng.fill_bytes(&mut key);
            let encoded = STANDARD.encode(key);
            write_private(path, encoded.as_bytes())?;
            Ok(Self(Zeroizing::new(key)))
        }
    }

    pub fn encrypt(&self, plaintext: &str) -> Result<String> {
        let cipher = Aes256Gcm::new_from_slice(self.0.as_ref())
            .map_err(|_| Error::Security("invalid encryption key".into()))?;
        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|_| Error::Security("credential encryption failed".into()))?;
        let mut payload = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        payload.extend_from_slice(&nonce_bytes);
        payload.extend_from_slice(&ciphertext);
        Ok(format!("{SEALED_PREFIX}{}", STANDARD.encode(payload)))
    }

    pub fn decrypt(&self, sealed: &str) -> Result<Zeroizing<String>> {
        let encoded = sealed
            .strip_prefix(SEALED_PREFIX)
            .ok_or_else(|| Error::Security("unknown credential envelope".into()))?;
        let payload = STANDARD
            .decode(encoded)
            .map_err(|_| Error::Security("credential envelope is corrupt".into()))?;
        if payload.len() <= NONCE_LEN {
            return Err(Error::Security("credential envelope is truncated".into()));
        }
        let (nonce_bytes, ciphertext) = payload.split_at(NONCE_LEN);
        let cipher = Aes256Gcm::new_from_slice(self.0.as_ref())
            .map_err(|_| Error::Security("invalid encryption key".into()))?;
        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| Error::Security("credential decryption failed".into()))?;
        String::from_utf8(plaintext)
            .map(Zeroizing::new)
            .map_err(|_| Error::Security("credential is not valid UTF-8".into()))
    }
}

#[cfg(unix)]
fn write_private(path: &Path, contents: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &Path, contents: &[u8]) -> Result<()> {
    fs::write(path, contents)?;
    Ok(())
}

pub fn hash_password(password: &str) -> Result<String> {
    validate_password(password)?;
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(Into::into)
}

pub fn verify_password(password: &str, encoded: &str) -> bool {
    PasswordHash::new(encoded)
        .ok()
        .and_then(|hash| {
            Argon2::default()
                .verify_password(password.as_bytes(), &hash)
                .ok()
        })
        .is_some()
}

pub fn validate_password(password: &str) -> Result<()> {
    if password.chars().count() < 10 {
        return Err(Error::Validation(
            "password must be at least 10 characters".into(),
        ));
    }
    if password.chars().count() > 256 {
        return Err(Error::Validation("password is too long".into()));
    }
    let classes = [
        password.chars().any(|c| c.is_ascii_lowercase()),
        password.chars().any(|c| c.is_ascii_uppercase()),
        password.chars().any(|c| c.is_ascii_digit()),
        password.chars().any(|c| !c.is_ascii_alphanumeric()),
    ]
    .into_iter()
    .filter(|v| *v)
    .count();
    if classes < 3 {
        return Err(Error::Validation(
            "password must mix at least three of: lowercase, uppercase, digits, symbols".into(),
        ));
    }
    Ok(())
}

/// Generate a URL-safe random token and its SHA-256 digest. Only the digest is
/// persisted; the token itself is shown once to the client.
pub fn generate_token() -> (String, String) {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let token = URL_SAFE_NO_PAD.encode(bytes);
    let digest = token_digest(&token);
    (token, digest)
}

pub fn token_digest(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub fn constant_time_eq(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

pub fn generate_password() -> String {
    // Ambiguous characters removed; always satisfies the policy.
    const LOWER: &[u8] = b"abcdefghijkmnopqrstuvwxyz";
    const UPPER: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ";
    const DIGITS: &[u8] = b"23456789";
    const SYMBOLS: &[u8] = b"!@#$%^&*-_=+";
    let mut rng = OsRng;
    let mut pick = |set: &[u8]| set[(rng.next_u32() as usize) % set.len()] as char;
    let mut chars: Vec<char> = (0..16)
        .map(|i| match i % 4 {
            0 => pick(LOWER),
            1 => pick(UPPER),
            2 => pick(DIGITS),
            _ => pick(SYMBOLS),
        })
        .collect();
    // Fisher-Yates with OS randomness.
    for i in (1..chars.len()).rev() {
        let j = (rng.next_u32() as usize) % (i + 1);
        chars.swap(i, j);
    }
    chars.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealing_roundtrip_and_tamper() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("master.key");
        let key = MasterKey::load_or_create(&key_path).unwrap();
        let sealed = key.encrypt("router-password").unwrap();
        assert!(!sealed.contains("router-password"));
        assert_eq!(key.decrypt(&sealed).unwrap().as_str(), "router-password");
        let key2 = MasterKey::load_or_create(&key_path).unwrap();
        assert_eq!(key2.decrypt(&sealed).unwrap().as_str(), "router-password");
        let mut tampered = sealed.clone();
        tampered.push('A');
        assert!(key.decrypt(&tampered).is_err());
    }

    #[test]
    fn passwords() {
        let hash = hash_password("CorrectHorse1!").unwrap();
        assert!(verify_password("CorrectHorse1!", &hash));
        assert!(!verify_password("WrongHorse1!", &hash));
        assert!(hash_password("short").is_err());
        assert!(hash_password("alllowercase").is_err());
    }

    #[test]
    fn tokens_are_opaque_and_unique() {
        let (a, ah) = generate_token();
        let (b, bh) = generate_token();
        assert_ne!(a, b);
        assert_ne!(ah, bh);
        assert_eq!(ah, token_digest(&a));
        assert!(constant_time_eq(&ah, &token_digest(&a)));
    }

    #[test]
    fn generated_password_meets_policy() {
        let pw = generate_password();
        assert!(validate_password(&pw).is_ok(), "generated: {pw}");
    }
}
