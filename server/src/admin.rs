use crate::security;
use anyhow::{bail, Result};
use sqlx::PgPool;

/// Legt einen Admin an oder setzt dessen Passwort neu.
pub async fn upsert_admin(pool: &PgPool, username: &str, password: &str) -> Result<()> {
    if !(3..=32).contains(&username.len())
        || !username
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
    {
        bail!("Benutzername: 3–32 Zeichen aus A–Z, a–z, 0–9, '.', '_', '-'");
    }
    if password.chars().count() < 12 {
        bail!("Passwort: mindestens 12 Zeichen");
    }
    let hash = security::hash_password(password)?;
    sqlx::query(
        "INSERT INTO admin_users (username, password_hash) VALUES ($1, $2) \
         ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash",
    )
    .bind(username)
    .bind(hash)
    .execute(pool)
    .await?;
    Ok(())
}
