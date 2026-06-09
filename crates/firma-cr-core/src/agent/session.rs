// SPDX-License-Identifier: GPL-3.0-or-later
//! Per-browser-session "env" state (DESIGN.md, reports/29).
//!
//! On `create_env` the agent mints a fresh RSA keypair and hands the web app
//! the public key (PEM). The PIN later arrives RSA-encrypted with that key and
//! is decrypted here with the env private key — so the PIN stays confidential
//! even over the plain-HTTP local channel.

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use rand::rngs::OsRng;
use rand::RngCore as _;
use rsa::pkcs8::{EncodePublicKey, LineEnding};
use rsa::{Oaep, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use rsa::sha2::Sha256;

const ENV_KEY_BITS: usize = 2048;

struct Env {
    private: RsaPrivateKey,
    pub_pem: String,
}

/// In-memory store of active browser-session envs. Wrap in `Arc<Mutex<…>>` for
/// the async HTTP layer.
#[derive(Default)]
pub struct EnvStore {
    envs: HashMap<String, Env>,
}

impl EnvStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mint a new env: returns `(envId, pubKeyPem)`. The web app encrypts the
    /// PIN with `pubKeyPem`; the matching private key stays here.
    pub fn create_env(&mut self) -> Result<(String, String), String> {
        let mut rng = OsRng;
        let private = RsaPrivateKey::new(&mut rng, ENV_KEY_BITS)
            .map_err(|e| format!("env keygen failed: {e}"))?;
        let pub_pem = RsaPublicKey::from(&private)
            .to_public_key_pem(LineEnding::LF)
            .map_err(|e| format!("pubkey PEM failed: {e}"))?;
        let id = gen_env_id();
        self.envs.insert(id.clone(), Env { private, pub_pem: pub_pem.clone() });
        Ok((id, pub_pem))
    }

    /// The public key PEM for an env, if it exists.
    pub fn pub_pem(&self, env_id: &str) -> Option<&str> {
        self.envs.get(env_id).map(|e| e.pub_pem.as_str())
    }

    pub fn contains(&self, env_id: &str) -> bool {
        self.envs.contains_key(env_id)
    }

    /// Drop an env (logout / end_session).
    pub fn remove(&mut self, env_id: &str) -> bool {
        self.envs.remove(env_id).is_some()
    }

    /// Decrypt a base64 client-encrypted PIN with the env private key. Tries
    /// RSA-OAEP-SHA256 (the WebCrypto default) then PKCS#1 v1.5, so it works
    /// whichever the client used. Returns `None` on unknown env / bad input.
    ///
    /// NOTE: the exact mode Idopte's client uses is an open item (report 29);
    /// accepting both keeps us correct until a live capture pins it down.
    pub fn decrypt_pin(&self, env_id: &str, b64_ciphertext: &str) -> Option<String> {
        let env = self.envs.get(env_id)?;
        let ct = STANDARD.decode(b64_ciphertext.trim()).ok()?;
        let pt = env
            .private
            .decrypt(Oaep::new::<Sha256>(), &ct)
            .ok()
            .or_else(|| env.private.decrypt(Pkcs1v15Encrypt, &ct).ok())?;
        String::from_utf8(pt).ok()
    }
}

fn gen_env_id() -> String {
    let mut rng = OsRng;
    let mut b = [0u8; 16];
    rng.fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs8::DecodePublicKey;

    /// Client side: encrypt a PIN with the published pubkey PEM (OAEP or PKCS1v15).
    fn client_encrypt(pub_pem: &str, pin: &str, oaep: bool) -> String {
        let pk = RsaPublicKey::from_public_key_pem(pub_pem).unwrap();
        let mut rng = OsRng;
        let ct = if oaep {
            pk.encrypt(&mut rng, Oaep::new::<Sha256>(), pin.as_bytes()).unwrap()
        } else {
            pk.encrypt(&mut rng, Pkcs1v15Encrypt, pin.as_bytes()).unwrap()
        };
        STANDARD.encode(ct)
    }

    #[test]
    fn create_env_yields_pubkey_pem_and_id() {
        let mut s = EnvStore::new();
        let (id, pem) = s.create_env().unwrap();
        assert!(!id.is_empty());
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        assert!(RsaPublicKey::from_public_key_pem(&pem).is_ok());
        assert!(s.contains(&id));
        assert_eq!(s.pub_pem(&id), Some(pem.as_str()));
    }

    #[test]
    fn envs_are_distinct() {
        let mut s = EnvStore::new();
        let (id1, pem1) = s.create_env().unwrap();
        let (id2, pem2) = s.create_env().unwrap();
        assert_ne!(id1, id2);
        assert_ne!(pem1, pem2);
    }

    #[test]
    fn pin_round_trips_oaep() {
        let mut s = EnvStore::new();
        let (id, pem) = s.create_env().unwrap();
        let enc = client_encrypt(&pem, "123456", true);
        assert_eq!(s.decrypt_pin(&id, &enc).as_deref(), Some("123456"));
    }

    #[test]
    fn pin_round_trips_pkcs1v15() {
        let mut s = EnvStore::new();
        let (id, pem) = s.create_env().unwrap();
        let enc = client_encrypt(&pem, "1234", false);
        assert_eq!(s.decrypt_pin(&id, &enc).as_deref(), Some("1234"));
    }

    #[test]
    fn unknown_env_yields_none() {
        let s = EnvStore::new();
        assert!(s.decrypt_pin("deadbeef", "AAAA").is_none());
        assert!(s.pub_pem("deadbeef").is_none());
        assert!(!s.contains("deadbeef"));
    }

    #[test]
    fn bad_ciphertext_yields_none() {
        let mut s = EnvStore::new();
        let (id, _pem) = s.create_env().unwrap();
        assert!(s.decrypt_pin(&id, "not valid base64 !!!").is_none());
        // valid base64, but not a valid ciphertext for our key:
        assert!(s.decrypt_pin(&id, &STANDARD.encode([0u8; 256])).is_none());
    }

    #[test]
    fn remove_env() {
        let mut s = EnvStore::new();
        let (id, _) = s.create_env().unwrap();
        assert!(s.remove(&id));
        assert!(!s.contains(&id));
        assert!(!s.remove(&id));
    }
}
