//! Zeitbasierte Einmalcodes (TOTP, RFC 6238) für die Zwei-Faktor-Anmeldung: SHA-1, 6 Stellen, 30 Sekunden, wie in
//! gängigen Authenticator-Apps. Eigenes kleines Modul statt zusätzlicher Abhängigkeit (HMAC kommt aus `ring`).

use ring::hmac;

/// Länge eines Zeitschritts in Sekunden.
pub const STEP_SECS: u64 = 30;
const DIGITS: u32 = 6;
const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Base32 (RFC 4648, ohne Auffüllung), wie es Authenticator-Apps erwarten.
pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in data {
        buf = (buf << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            out.push(ALPHABET[((buf >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let (mut buf, mut bits) = (0u32, 0u32);
    let mut out = Vec::new();
    for c in s.bytes().filter(|c| *c != b' ' && *c != b'=') {
        let v = ALPHABET.iter().position(|a| *a == c.to_ascii_uppercase())? as u32;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            out.push((buf >> (bits - 8)) as u8);
            bits -= 8;
        }
    }
    Some(out)
}

/// Code für einen Zeitschritt.
pub fn code_for_step(secret: &[u8], step: u64) -> u32 {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let tag = hmac::sign(&key, &step.to_be_bytes());
    let h = tag.as_ref();
    let off = (h[19] & 0x0f) as usize;
    let bin = (u32::from(h[off]) & 0x7f) << 24
        | u32::from(h[off + 1]) << 16
        | u32::from(h[off + 2]) << 8
        | u32::from(h[off + 3]);
    bin % 10u32.pow(DIGITS)
}

/// Prüft einen eingegebenen Code gegen den aktuellen Zeitschritt und je einen davor und danach (Uhrenabweichung).
/// Gibt den passenden Zeitschritt zurück; Schritte bis `after` (der zuletzt akzeptierte) gelten nicht noch einmal.
pub fn verify(secret: &[u8], input: &str, now_secs: u64, after: Option<i64>) -> Option<i64> {
    let input = input.trim();
    if input.len() != DIGITS as usize || !input.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let wanted: u32 = input.parse().ok()?;
    let current = (now_secs / STEP_SECS) as i64;
    let mut found = None;
    // Alle drei Schritte prüfen (konstante Arbeit, kein früher Abbruch bei Treffer).
    for step in [current - 1, current, current + 1] {
        if step < 0 {
            continue;
        }
        let ok = code_for_step(secret, step as u64) == wanted;
        if ok && after.is_none_or(|a| step > a) {
            found = Some(step);
        }
    }
    found
}

/// Zufälliges Geheimnis (20 Byte, wie von SHA-1-Apps üblich).
pub fn new_secret() -> Vec<u8> {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut b = vec![0u8; 20];
    SystemRandom::new().fill(&mut b).expect("Zufallsquelle");
    b
}

/// otpauth-Adresse für den QR-Code (Name und Aussteller werden kodiert).
pub fn otpauth_uri(secret_b32: &str, account: &str) -> String {
    fn enc(s: &str) -> String {
        s.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    (b as char).to_string()
                }
                _ => format!("%{b:02X}"),
            })
            .collect()
    }
    format!(
        "otpauth://totp/patchwatch:{}?secret={secret_b32}&issuer=patchwatch&algorithm=SHA1&digits={DIGITS}&period={STEP_SECS}",
        enc(account)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6238_vector() {
        // RFC 6238, Anhang B: Geheimnis "12345678901234567890", T = 59 s -> 94287082 (8 Stellen), also 287082 bei 6.
        let s = b"12345678901234567890";
        assert_eq!(code_for_step(s, 59 / 30), 287082);
        assert_eq!(code_for_step(s, 1111111109 / 30), 81804);
    }

    #[test]
    fn base32_roundtrip() {
        let data = b"12345678901234567890";
        let enc = base32_encode(data);
        assert_eq!(enc, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        assert_eq!(base32_decode(&enc).unwrap(), data);
        assert!(base32_decode("1!").is_none());
    }

    #[test]
    fn verify_window_and_replay() {
        let s = b"12345678901234567890";
        let now = 1_000_000u64;
        let step = (now / STEP_SECS) as i64;
        let code = format!("{:06}", code_for_step(s, step as u64));
        assert_eq!(verify(s, &code, now, None), Some(step));
        // Einen Schritt später noch gültig, aber nicht mehr, wenn der Schritt schon verbraucht ist.
        assert_eq!(verify(s, &code, now + 30, None), Some(step));
        assert_eq!(verify(s, &code, now, Some(step)), None);
        assert_eq!(verify(s, &code, now + 120, None), None);
        assert_eq!(verify(s, "12345", now, None), None);
        assert_eq!(verify(s, "abcdef", now, None), None);
    }
}
