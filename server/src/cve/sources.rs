//! Verwaltung der CVE-Quellen (Tabelle `cve_sources`): Seed aus der Konfiguration, an/aus, Spiegel-URL, Geheimnis.
//! Quellen mit `enrich_only` (OSV, NVD, CISA KEV) reichern nur bereits bekannte CVEs an und importieren nie voll.

use super::debian::Debian;
use super::kev::Kev;
use super::nvd::Nvd;
use super::osv::Osv;
use super::ubuntu::Ubuntu;
use super::CveSource;
use crate::notify::{crypto, ssrf};
use crate::state::AppState;
use anyhow::{anyhow, Result};
use serde::Serialize;

pub const KNOWN: [&str; 5] = ["debian", "ubuntu", "osv", "nvd", "cisa_kev"];
const BUILTIN: [&str; 2] = ["debian", "ubuntu"];

pub fn is_known(name: &str) -> bool {
    KNOWN.contains(&name)
}

pub fn is_builtin(name: &str) -> bool {
    BUILTIN.contains(&name)
}

/// Quellen, die nur bereits bekannte CVEs anreichern (kein Vollimport).
pub fn enrich_only(name: &str) -> bool {
    matches!(name, "osv" | "nvd" | "cisa_kev")
}

/// Nimmt die Quelle ein Geheimnis (API-Schlüssel) an?
pub fn takes_secret(name: &str) -> bool {
    name == "nvd"
}

/// Spiegel-URLs sind für die Quellen mit festem Endpunkt erlaubt (nicht für die Debian/Ubuntu-Tracker).
pub fn takes_base_url(name: &str) -> bool {
    matches!(name, "osv" | "nvd" | "cisa_kev")
}

/// AAD der Verschlüsselung: der Quellenname, damit ein Geheimnis nicht für eine andere Quelle taugt.
fn aad(name: &str) -> String {
    format!("cve_source:{name}")
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct SourceRow {
    pub name: String,
    pub enabled: bool,
    pub base_url: Option<String>,
    /// Nie das Geheimnis selbst, nur ob eines gespeichert ist.
    pub secret_set: bool,
}

/// Legt die in der Konfiguration genannten Quellen an, falls es sie noch nicht gibt (ein Abschalten bleibt bestehen).
pub async fn ensure_seeded(state: &AppState) -> Result<()> {
    for name in BUILTIN
        .iter()
        .map(|s| s.to_string())
        .chain(state.cfg.cve.sources.iter().cloned())
    {
        if !is_known(&name) || (is_builtin(&name) && !state.cfg.cve.sources.contains(&name)) {
            continue;
        }
        sqlx::query("INSERT INTO cve_sources (name) VALUES ($1) ON CONFLICT DO NOTHING")
            .bind(&name)
            .execute(&state.pool)
            .await?;
    }
    Ok(())
}

pub async fn list(state: &AppState) -> Result<Vec<SourceRow>> {
    ensure_seeded(state).await?;
    Ok(sqlx::query_as(
        "SELECT name, enabled, base_url, secret IS NOT NULL AS secret_set FROM cve_sources ORDER BY name",
    )
    .fetch_all(&state.pool)
    .await?)
}

/// Geprüfte Spiegel-URL: nur http(s) ohne Zugangsdaten/Query, Ziel nach den SSRF-Regeln (Loopback/Link-Local immer gesperrt,
/// private Ziele nur bei exaktem Treffer in `notify_allowed_hosts`).
pub async fn check_base_url(state: &AppState, raw: &str) -> Result<ssrf::Target, String> {
    let url = ssrf::parse_url(raw, false).map_err(|e| e.message().to_string())?;
    ssrf::resolve(url, &state.cfg.notify_allowed_hosts)
        .await
        .map_err(|e| e.message().to_string())
}

async fn decrypt_secret(state: &AppState, name: &str, blob: &[u8]) -> Result<String> {
    let key = state
        .cfg
        .secret_key
        .as_ref()
        .ok_or_else(|| anyhow!("PATCHWATCH_SECRET_KEY fehlt"))?;
    crypto::decrypt(key.bytes(), &aad(name), blob)
}

pub async fn encrypt_secret(
    state: &AppState,
    name: &str,
    plaintext: &str,
) -> Result<Vec<u8>, String> {
    let key = state
        .cfg
        .secret_key
        .as_ref()
        .ok_or("Ohne PATCHWATCH_SECRET_KEY lassen sich keine Geheimnisse speichern")?;
    crypto::encrypt(key.bytes(), &aad(name), plaintext)
        .map_err(|_| "Verschlüsselung fehlgeschlagen".to_string())
}

/// Baut die aktiven (eingeschalteten) Quellen. Eine Quelle, die sich nicht bauen lässt (z. B. Spiegel nicht mehr
/// erlaubt), fehlt nicht stillschweigend: sie wird als Fehler im Feed-Zustand sichtbar (siehe `refresh_all`).
pub async fn build_enabled(state: &AppState) -> Vec<(String, Result<Box<dyn CveSource>>)> {
    if let Err(e) = ensure_seeded(state).await {
        return vec![("cve_sources".into(), Err(e))];
    }
    let rows = match sqlx::query_as::<_, (String, Option<String>, Option<Vec<u8>>)>(
        "SELECT name, base_url, secret FROM cve_sources WHERE enabled ORDER BY name",
    )
    .fetch_all(&state.pool)
    .await
    {
        Ok(r) => r,
        Err(e) => return vec![("cve_sources".into(), Err(e.into()))],
    };
    let mut out = Vec::new();
    for (name, base_url, secret) in rows {
        let built = build_one(state, &name, base_url.as_deref(), secret.as_deref()).await;
        out.push((name, built));
    }
    out
}

async fn build_one(
    state: &AppState,
    name: &str,
    base_url: Option<&str>,
    secret: Option<&[u8]>,
) -> Result<Box<dyn CveSource>> {
    let c = &state.cfg.cve;
    // Spiegel-Override: bei jedem Bau erneut geprüft (DNS kann sich ändern) und über einen an die Adresse gebundenen Client.
    let (base, client) = match base_url {
        Some(raw) => {
            let target = check_base_url(state, raw).await.map_err(|m| anyhow!(m))?;
            let client =
                ssrf::pinned_client(&target).map_err(|_| anyhow!("HTTP-Client nicht baubar"))?;
            (Some(raw.trim_end_matches('/').to_owned()), Some(client))
        }
        None => (None, None),
    };
    Ok(match name {
        "ubuntu" => Box::new(Ubuntu::new(c)),
        "debian" => Box::new(Debian::new(c)),
        "osv" => Box::new(Osv::with_base(c, base, client)),
        "nvd" => {
            let key = match secret {
                Some(blob) => Some(decrypt_secret(state, name, blob).await?),
                None => None,
            };
            Box::new(Nvd::new(c, base, client, key))
        }
        "cisa_kev" => Box::new(Kev::new(c, base, client)),
        _ => return Err(anyhow!("unbekannte Quelle")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_types_and_capabilities() {
        assert!(is_known("nvd") && !is_known("evil"));
        assert!(is_builtin("debian") && !is_builtin("nvd"));
        assert!(enrich_only("nvd") && enrich_only("osv") && enrich_only("cisa_kev"));
        assert!(!enrich_only("debian") && !enrich_only("ubuntu"));
        assert!(takes_secret("nvd") && !takes_secret("osv"));
        assert!(!takes_base_url("debian"));
        assert_eq!(aad("nvd"), "cve_source:nvd");
    }
}
