//! Verschlüsselung der Kanal-Geheimnisse (XChaCha20-Poly1305).
//!
//! Format: `nonce (24 Byte) || ciphertext+tag`. Der Kanalname geht als Associated Data ein: Ein
//! Geheimnis, das für `discord` verschlüsselt wurde, lässt sich nicht als `gotify`-Geheimnis
//! entschlüsseln (z. B. nach einem manuellen Vertauschen von Zeilen in der Datenbank).

use anyhow::{anyhow, bail, Result};
use argon2::password_hash::rand_core::{OsRng, RngCore};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

const NONCE_LEN: usize = 24;

pub fn encrypt(key: &[u8; 32], kind: &str, plaintext: &str) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_bytes(),
                aad: kind.as_bytes(),
            },
        )
        .map_err(|_| anyhow!("Verschlüsselung fehlgeschlagen"))?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn decrypt(key: &[u8; 32], kind: &str, blob: &[u8]) -> Result<String> {
    if blob.len() < NONCE_LEN + 16 {
        bail!("gespeichertes Geheimnis ist beschädigt");
    }
    let (nonce, ct) = blob.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(key.into());
    let pt = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ct,
                aad: kind.as_bytes(),
            },
        )
        .map_err(|_| {
            anyhow!("Geheimnis lässt sich nicht entschlüsseln (falscher PATCHWATCH_SECRET_KEY?)")
        })?;
    String::from_utf8(pt).map_err(|_| anyhow!("gespeichertes Geheimnis ist beschädigt"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [42; 32];

    #[test]
    fn roundtrip_and_fresh_nonce() {
        let a = encrypt(&KEY, "gotify", "app-token").unwrap();
        let b = encrypt(&KEY, "gotify", "app-token").unwrap();
        assert_ne!(a, b, "jede Verschlüsselung nutzt eine neue Nonce");
        assert!(!String::from_utf8_lossy(&a).contains("app-token"));
        assert_eq!(decrypt(&KEY, "gotify", &a).unwrap(), "app-token");
    }

    #[test]
    fn wrong_key_wrong_channel_or_tampering_fail() {
        let blob = encrypt(&KEY, "discord", "https://discord.com/api/webhooks/1/x").unwrap();
        assert!(decrypt(&[1; 32], "discord", &blob).is_err());
        // Kanalname ist Associated Data.
        assert!(decrypt(&KEY, "gotify", &blob).is_err());
        let mut bad = blob.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(decrypt(&KEY, "discord", &bad).is_err());
        assert!(decrypt(&KEY, "discord", &blob[..10]).is_err());
    }
}
