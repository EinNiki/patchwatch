use argon2::password_hash::rand_core::{OsRng, RngCore};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use subtle::ConstantTimeEq;

fn random_b64(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    OsRng.fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

/// Agent-Token: Präfix erleichtert Secret-Scanning, 256 Bit Zufall.
pub fn new_agent_token() -> String {
    format!("pw_{}", random_b64(32))
}

pub fn new_session_id() -> String {
    random_b64(32)
}

pub fn new_csrf_token() -> String {
    random_b64(24)
}

pub fn sha256(s: &str) -> Vec<u8> {
    Sha256::digest(s.as_bytes()).to_vec()
}

pub fn ct_eq(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

pub fn hash_password(pw: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(pw.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow::anyhow!("argon2: {e}"))
}

pub fn verify_password(hash: &str, pw: &str) -> bool {
    PasswordHash::new(hash)
        .map(|h| Argon2::default().verify_password(pw.as_bytes(), &h).is_ok())
        .unwrap_or(false)
}

/// Hash für unbekannte Benutzer, damit Login-Zeiten nicht verraten, ob ein Konto existiert.
pub fn dummy_hash() -> &'static str {
    static H: OnceLock<String> = OnceLock::new();
    H.get_or_init(|| hash_password("dummy-password-for-timing").expect("argon2"))
}

pub const SESSION_COOKIE: &str = "pw_session";

pub fn session_cookie(value: &str, max_age_secs: i64, secure: bool) -> String {
    let secure = if secure { "; Secure" } else { "" };
    format!("{SESSION_COOKIE}={value}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age_secs}{secure}")
}

pub fn cookie_value<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header.split(';').find_map(|p| {
        let (k, v) = p.trim().split_once('=')?;
        (k == name).then_some(v)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_unique_and_prefixed() {
        let (a, b) = (new_agent_token(), new_agent_token());
        assert!(a.starts_with("pw_") && a.len() > 40);
        assert_ne!(a, b);
    }

    #[test]
    fn password_roundtrip() {
        let h = hash_password("correct horse battery").unwrap();
        assert!(h.starts_with("$argon2id$"));
        assert!(verify_password(&h, "correct horse battery"));
        assert!(!verify_password(&h, "wrong"));
        assert!(!verify_password("kein-hash", "x"));
    }

    #[test]
    fn cookie_parsing() {
        assert_eq!(
            cookie_value("a=1; pw_session=xyz; b=2", SESSION_COOKIE),
            Some("xyz")
        );
        assert_eq!(cookie_value("a=1", SESSION_COOKIE), None);
        let c = session_cookie("v", 60, true);
        assert!(c.contains("HttpOnly") && c.contains("SameSite=Strict") && c.contains("Secure"));
        assert!(!session_cookie("v", 60, false).contains("Secure"));
    }

    #[test]
    fn constant_time_compare() {
        assert!(ct_eq("abc", "abc"));
        assert!(!ct_eq("abc", "abd"));
        assert!(!ct_eq("abc", "ab"));
    }
}
