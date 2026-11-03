use crate::security;
use anyhow::{bail, Result};
use argon2::password_hash::rand_core::{OsRng, RngCore};
use sqlx::PgPool;

pub const MIN_PASSWORD_CHARS: usize = 12;

/// Früher ausgelieferte Standard-Passwörter. Sie sind öffentlich bekannt: sie werden nie mehr angelegt, nie als
/// neues Passwort akzeptiert, und bestehende Konten damit müssen das Passwort beim nächsten Login ändern.
/// (Der Wert steht nur noch hier, damit er erkannt und abgelehnt werden kann.)
pub const KNOWN_DEFAULT_PASSWORDS: &[&str] = &["patchwatch-change-me"];

/// Prüft ein neues Passwort (Länge, bekannter Standardwert).
pub fn check_new_password(password: &str) -> Result<()> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        bail!("Passwort: mindestens {MIN_PASSWORD_CHARS} Zeichen");
    }
    if KNOWN_DEFAULT_PASSWORDS.contains(&password) {
        bail!("Passwort: dieser Wert ist ein bekanntes Standardpasswort und nicht erlaubt");
    }
    Ok(())
}

/// Legt einen Admin an oder setzt dessen Passwort neu (vom Betreiber gewählt: kein Zwangswechsel).
pub async fn upsert_admin(pool: &PgPool, username: &str, password: &str) -> Result<()> {
    upsert_admin_with(pool, username, password, false).await
}

pub async fn upsert_admin_with(
    pool: &PgPool,
    username: &str,
    password: &str,
    must_change: bool,
) -> Result<()> {
    if !(3..=32).contains(&username.len())
        || !username
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
    {
        bail!("Benutzername: 3–32 Zeichen aus A–Z, a–z, 0–9, '.', '_', '-'");
    }
    check_new_password(password)?;
    let hash = security::hash_password(password)?;
    sqlx::query(
        "INSERT INTO admin_users (username, password_hash, must_change_password) VALUES ($1, $2, $3) \
         ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash, \
         must_change_password = EXCLUDED.must_change_password",
    )
    .bind(username)
    .bind(hash)
    .bind(must_change)
    .execute(pool)
    .await?;
    Ok(())
}

/// Zufallspasswort aus dem CSPRNG des Betriebssystems: 32 Zeichen aus 62 (ca. 190 Bit), ohne Modulo-Verzerrung.
pub fn random_password() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut out = String::with_capacity(32);
    let mut buf = [0u8; 64];
    while out.len() < 32 {
        OsRng.fill_bytes(&mut buf);
        for b in buf {
            // 248 = 4 * 62: Werte darüber verwerfen, damit jedes Zeichen gleich wahrscheinlich ist.
            if b < 248 && out.len() < 32 {
                out.push(ALPHABET[(b % 62) as usize] as char);
            }
        }
    }
    out
}

#[derive(Debug, PartialEq, Eq)]
pub enum Bootstrap {
    /// Es gibt schon einen Admin: nichts getan.
    Existing,
    /// Admin `admin` mit dem vom Betreiber gesetzten Passwort angelegt.
    FromEnv,
    /// Admin `admin` mit Zufallspasswort angelegt (nur hier im Rückgabewert, nie gespeichert); der Aufrufer zeigt
    /// es genau einmal an. Das Konto muss das Passwort beim ersten Login ändern.
    Random(String),
}

/// Erster Start: legt den Admin an, solange noch keiner existiert. Nie mit einem festen, bekannten Wert.
/// `env_password` stammt aus `PATCHWATCH_ADMIN_PASSWORD` (explizit gesetzt: mindestens 12 Zeichen, kein bekannter
/// Standardwert, sonst Fehler -- der Server startet dann nicht, statt still auf etwas anderes auszuweichen).
pub async fn bootstrap_admin(pool: &PgPool, env_password: Option<&str>) -> Result<Bootstrap> {
    let any: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM admin_users)")
        .fetch_one(pool)
        .await?;
    if any {
        return Ok(Bootstrap::Existing);
    }
    match env_password.filter(|p| !p.is_empty()) {
        Some(pw) => {
            upsert_admin_with(pool, "admin", pw, false).await?;
            Ok(Bootstrap::FromEnv)
        }
        None => {
            let pw = random_password();
            upsert_admin_with(pool, "admin", &pw, true).await?;
            Ok(Bootstrap::Random(pw))
        }
    }
}

/// Markiert Konten, deren Passwort noch einem bekannten Standardwert entspricht (Altinstallationen), per
/// Argon2-Verify als "Passwort muss geändert werden". Gibt die betroffenen Benutzernamen zurück.
pub async fn flag_default_passwords(pool: &PgPool) -> Result<Vec<String>> {
    let rows: Vec<(i64, String, String)> = sqlx::query_as(
        "SELECT id, username, password_hash FROM admin_users WHERE NOT must_change_password",
    )
    .fetch_all(pool)
    .await?;
    let mut flagged = Vec::new();
    for (id, username, hash) in rows {
        let is_default = tokio::task::spawn_blocking(move || {
            KNOWN_DEFAULT_PASSWORDS
                .iter()
                .any(|p| security::verify_password(&hash, p))
        })
        .await?;
        if is_default {
            sqlx::query("UPDATE admin_users SET must_change_password = true WHERE id = $1")
                .bind(id)
                .execute(pool)
                .await?;
            // Offene Sitzungen mit dem bekannten Passwort enden, der nächste Login erzwingt den Wechsel.
            sqlx::query("DELETE FROM sessions WHERE admin_id = $1")
                .bind(id)
                .execute(pool)
                .await?;
            flagged.push(username);
        }
    }
    Ok(flagged)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_password_is_long_alphanumeric_and_unique() {
        let a = random_password();
        let b = random_password();
        assert!(a.len() >= 24 && a.len() == 32);
        assert!(a.chars().all(|c| c.is_ascii_alphanumeric()));
        assert_ne!(a, b);
    }

    #[test]
    fn known_default_and_short_passwords_are_rejected() {
        assert!(check_new_password(KNOWN_DEFAULT_PASSWORDS[0]).is_err());
        assert!(check_new_password("kurz").is_err());
        assert!(check_new_password("ein-langes-passwort").is_ok());
    }
}
