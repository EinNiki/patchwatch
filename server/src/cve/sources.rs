//! Verwaltung der CVE-Quellen (Tabelle `cve_sources`): Seed aus der Konfiguration, an/aus, Spiegel-URL, Geheimnis.
//! Quellen mit `enrich_only` (OSV, NVD, CISA KEV) reichern nur bereits bekannte CVEs an und importieren nie voll.

use super::debian::Debian;
use super::kev::Kev;
use super::nvd::Nvd;
use super::osv::Osv;
use super::ubuntu::Ubuntu;
use super::CveSource;
use crate::notify::secret_target;
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

/// OSV kann auf ein Ökosystem eingeschränkt werden (z. B. `Debian:13`).
pub fn takes_ecosystem(kind: &str) -> bool {
    kind == "osv"
}

/// Anzeigename des Typs (Vorgabe für den Namen beim Hinzufügen).
pub fn kind_title(kind: &str) -> &'static str {
    match kind {
        "debian" => "Debian",
        "ubuntu" => "Ubuntu",
        "osv" => "OSV",
        "nvd" => "NVD",
        "cisa_kev" => "CISA KEV",
        _ => "Quelle",
    }
}

/// AAD der Verschlüsselung: die stabile Quellen-ID, damit ein Geheimnis nicht für eine andere Quelle taugt.
/// Bestehende Quellen behalten ihre ID (= alter Name), die AAD ist für sie unverändert.
fn aad(id: &str) -> String {
    format!("cve_source:{id}")
}

/// Neue stabile ID: Typ plus Zufall (nie vom Anzeigenamen abgeleitet, der sich ändern darf).
pub fn new_id(kind: &str) -> String {
    use argon2::password_hash::rand_core::{OsRng, RngCore};
    let mut b = [0u8; 5];
    OsRng.fill_bytes(&mut b);
    format!(
        "{kind}-{}",
        b.iter().map(|x| format!("{x:02x}")).collect::<String>()
    )
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct SourceRow {
    pub id: String,
    pub kind: String,
    pub label: String,
    pub enabled: bool,
    pub base_url: Option<String>,
    pub ecosystem: Option<String>,
    /// Nie das Geheimnis selbst, nur ob eines gespeichert ist.
    pub secret_set: bool,
}

const SEEDED_KEY: &str = "cve_sources.seeded";

/// Legt beim ersten Start Debian, Ubuntu und die in der Konfiguration genannten Quellen an. Danach nie wieder:
/// eine gelöschte Quelle kommt nicht von selbst zurück.
pub async fn ensure_seeded(state: &AppState) -> Result<()> {
    let done: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM settings WHERE key = $1)")
        .bind(SEEDED_KEY)
        .fetch_one(&state.pool)
        .await?;
    if done {
        return Ok(());
    }
    let mut tx = state.pool.begin().await?;
    for kind in BUILTIN
        .iter()
        .map(|s| s.to_string())
        .chain(state.cfg.cve.sources.iter().cloned())
    {
        if !is_known(&kind) || (is_builtin(&kind) && !state.cfg.cve.sources.contains(&kind)) {
            continue;
        }
        // Legacy-Schreibweise: die erste Quelle eines Typs hat die ID = Typ.
        sqlx::query(
            "INSERT INTO cve_sources (id, kind, label) VALUES ($1, $1, $2) ON CONFLICT DO NOTHING",
        )
        .bind(&kind)
        .bind(kind_title(&kind))
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query(
        "INSERT INTO settings (key, value) VALUES ($1, 'true'::jsonb) ON CONFLICT DO NOTHING",
    )
    .bind(SEEDED_KEY)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

pub async fn list(state: &AppState) -> Result<Vec<SourceRow>> {
    ensure_seeded(state).await?;
    Ok(sqlx::query_as(
        "SELECT id, kind, label, enabled, base_url, ecosystem, secret IS NOT NULL AS secret_set \
         FROM cve_sources WHERE deleted_at IS NULL ORDER BY created_at, id",
    )
    .fetch_all(&state.pool)
    .await?)
}

/// Gibt es für diesen Typ mindestens eine eingeschaltete, nicht gelöschte Quelle?
pub async fn has_active(pool: &sqlx::PgPool, kind: &str) -> sqlx::Result<bool> {
    sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM cve_sources WHERE kind = $1 AND enabled AND deleted_at IS NULL)")
        .bind(kind)
        .fetch_one(pool)
        .await
}

/// Endgültig entfernen, was seit mehr als 30 Tagen gelöscht ist: Quelle, ihre Zeilen, Feed-Zustand und Intervall.
pub async fn purge_deleted(pool: &sqlx::PgPool) -> sqlx::Result<u64> {
    let ids: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM cve_sources WHERE deleted_at IS NOT NULL AND deleted_at < now() - interval '30 days'",
    )
    .fetch_all(pool)
    .await?;
    for id in &ids {
        let mut tx = pool.begin().await?;
        sqlx::query("DELETE FROM cve_source_status WHERE source_id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM feed_state WHERE source = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM settings WHERE key = $1")
            .bind(format!("schedule.feeds.interval_minutes.{id}"))
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM cve_sources WHERE id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
    }
    Ok(ids.len() as u64)
}

/// Geprüfte Spiegel-URL: nur http(s) ohne Zugangsdaten/Query, Ziel nach den SSRF-Regeln (Loopback/Link-Local immer gesperrt,
/// private Ziele nur bei exaktem Treffer in `notify_allowed_hosts`).
pub async fn check_base_url(state: &AppState, raw: &str) -> Result<ssrf::Target, String> {
    let url = ssrf::parse_url(raw, false).map_err(|e| e.message().to_string())?;
    ssrf::resolve(url, &state.cfg.notify_allowed_hosts)
        .await
        .map_err(|e| e.message().to_string())
}

/// Bekannte Webseiten (keine Feeds): welcher Quellentyp gehört dazu? Für verständliche Fehlertexte und den Typ-Vorschlag.
/// API-Adressen (api.osv.dev, services.nvd.nist.gov, cisa.gov/….json) sind echte Feed-Adressen und gehören nicht dazu.
pub fn suggest_kind(raw: &str) -> Option<&'static str> {
    let url = reqwest::Url::parse(raw.trim()).ok()?;
    let host = url.host_str()?.to_ascii_lowercase();
    let path = url.path();
    match host.as_str() {
        "ubuntu.com" | "www.ubuntu.com" if path.starts_with("/security") => Some("ubuntu"),
        "security-tracker.debian.org" => Some("debian"),
        "nvd.nist.gov" => Some("nvd"),
        "osv.dev" | "www.osv.dev" => Some("osv"),
        "www.cisa.gov" | "cisa.gov" if !path.ends_with(".json") => Some("cisa_kev"),
        _ => None,
    }
}

/// Verständlicher Fehlertext, wenn die Adresse eine bekannte Webseite statt eines Feeds ist (sonst `None`).
pub fn url_problem(kind: &str, raw: &str) -> Option<String> {
    let page = suggest_kind(raw)?;
    let (title, wanted) = (kind_title(kind), kind_title(page));
    Some(if page == kind {
        format!("Das ist die Webseite von {wanted}, kein Feed. Lass die Adresse leer, dann wird die Standardadresse genutzt.")
    } else if is_builtin(page) {
        format!("Das ist die Webseite von {wanted} und kein unterstützter Feed für den Typ {title}. {wanted} ist als eigener Typ vorhanden und braucht keine Adresse: wähle den Typ „{wanted}“.")
    } else {
        format!("Das ist die Webseite von {wanted} und kein unterstützter Feed für den Typ {title}. Wähle dafür den Typ „{wanted}“.")
    })
}

async fn decrypt_secret(state: &AppState, id: &str, blob: &[u8]) -> Result<String> {
    let key = state
        .cfg
        .secret_key
        .as_ref()
        .ok_or_else(|| anyhow!("PATCHWATCH_SECRET_KEY fehlt"))?;
    crypto::decrypt(key.bytes(), &aad(id), blob)
}

pub async fn encrypt_secret(
    state: &AppState,
    id: &str,
    plaintext: &str,
) -> Result<Vec<u8>, String> {
    let key = state
        .cfg
        .secret_key
        .as_ref()
        .ok_or("Ohne PATCHWATCH_SECRET_KEY lassen sich keine Geheimnisse speichern")?;
    crypto::encrypt(key.bytes(), &aad(id), plaintext)
        .map_err(|_| "Verschlüsselung fehlgeschlagen".to_string())
}

/// Eine zu bauende Quelle: stabile ID, Typ und das Ergebnis des Baus.
pub struct Built {
    pub id: String,
    pub kind: String,
    pub source: Result<Box<dyn CveSource>>,
}

/// Baut die aktiven (eingeschalteten, nicht gelöschten) Quellen. Eine Quelle, die sich nicht bauen lässt (z. B. Spiegel nicht
/// mehr erlaubt), fehlt nicht stillschweigend: sie wird als Fehler im Feed-Zustand sichtbar (siehe `refresh_all`).
pub async fn build_enabled(state: &AppState) -> Vec<Built> {
    let fail = |e: anyhow::Error| {
        vec![Built {
            id: "cve_sources".into(),
            kind: "cve_sources".into(),
            source: Err(e),
        }]
    };
    if let Err(e) = ensure_seeded(state).await {
        return fail(e);
    }
    let rows = match sqlx::query_as::<_, (String, String, Option<String>, Option<String>, Option<Vec<u8>>)>(
        "SELECT id, kind, base_url, ecosystem, secret FROM cve_sources WHERE enabled AND deleted_at IS NULL ORDER BY created_at, id",
    )
    .fetch_all(&state.pool)
    .await
    {
        Ok(r) => r,
        Err(e) => return fail(e.into()),
    };
    let mut out = Vec::new();
    for (id, kind, base_url, ecosystem, secret) in rows {
        let source = build_one(
            state,
            &id,
            &kind,
            base_url.as_deref(),
            ecosystem,
            secret.as_deref(),
        )
        .await;
        out.push(Built { id, kind, source });
    }
    out
}

async fn build_one(
    state: &AppState,
    id: &str,
    kind: &str,
    base_url: Option<&str>,
    ecosystem: Option<String>,
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
    Ok(match kind {
        "ubuntu" => Box::new(Ubuntu::new(c)),
        "debian" => Box::new(Debian::new(c)),
        "osv" => Box::new(Osv::with_base(c, base, client).with_ecosystem(ecosystem)),
        "nvd" => {
            // Defense in depth: auch ein früher gespeicherter Schlüssel geht nie über http:// an einen nicht erlaubten Host.
            if secret.is_some() {
                let target = base.as_deref().and_then(secret_target::Target::from_url);
                if let Some(m) = secret_target::cleartext_problem(
                    target.as_ref(),
                    &state.cfg.notify_allowed_hosts,
                ) {
                    return Err(anyhow!(m));
                }
            }
            let key = match secret {
                Some(blob) => Some(decrypt_secret(state, id, blob).await?),
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
        assert!(new_id("osv").starts_with("osv-") && new_id("osv") != new_id("osv"));
        assert_eq!(
            suggest_kind("https://ubuntu.com/security/cves"),
            Some("ubuntu")
        );
        assert_eq!(
            suggest_kind("https://security-tracker.debian.org/tracker/"),
            Some("debian")
        );
        assert_eq!(suggest_kind("https://nvd.nist.gov/vuln"), Some("nvd"));
        assert_eq!(suggest_kind("https://osv.dev/list"), Some("osv"));
        assert_eq!(suggest_kind("https://api.osv.dev"), None);
        assert_eq!(suggest_kind("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"), None);
        assert!(url_problem("osv", "https://ubuntu.com/security/cves")
            .unwrap()
            .contains("Typ „Ubuntu“"));
        assert!(url_problem("osv", "https://mirror.example.org").is_none());
        assert_eq!(suggest_kind("https://mirror.example.org/osv"), None);
    }
}
