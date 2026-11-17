//! Ereignis „Neues Image verfügbar“: einmal je Referenz und neuem Stand der Registry (nicht bei jeder Prüfung).
//! Der Stand ist bei gleitenden Tags der Digest, bei festen Versionen die Kombination der neuesten Versionen.
use super::view;
use super::worker::Key;
use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::PgPool;
use std::collections::BTreeMap;

/// Merker eines Stands für das Ereignis. Leer, wenn die Prüfung nichts Verwertbares ergab.
fn fingerprint(
    digest: Option<&str>,
    patch: Option<&str>,
    minor: Option<&str>,
    major: Option<&str>,
) -> String {
    match digest {
        Some(d) => d.to_owned(),
        None => format!(
            "{}|{}|{}",
            patch.unwrap_or(""),
            minor.unwrap_or(""),
            major.unwrap_or("")
        ),
    }
}

#[derive(sqlx::FromRow)]
struct Check {
    registry: String,
    repository: String,
    tag: String,
    registry_digest: Option<String>,
    newest_patch: Option<String>,
    newest_minor: Option<String>,
    newest_major: Option<String>,
    notified_for: Option<String>,
}

/// Legt für jede Referenz mit neuem Stand und mindestens einem veralteten Container ein Ereignis an. Gibt die Zahl
/// der angelegten Ereignisse zurück.
pub async fn announce(pool: &PgPool, now: DateTime<Utc>) -> sqlx::Result<usize> {
    let checks: Vec<Check> = sqlx::query_as(
        "SELECT registry, repository, tag, registry_digest, newest_patch, newest_minor, newest_major, notified_for \
         FROM container_image_checks WHERE platform = '' AND status = 'ok'",
    )
    .fetch_all(pool)
    .await?;
    let stand: BTreeMap<Key, &Check> = checks
        .iter()
        .map(|c| ((c.registry.clone(), c.repository.clone(), c.tag.clone()), c))
        .collect();
    // Veraltete Container je Referenz.
    let mut stale: BTreeMap<Key, Vec<&view::ContainerView>> = BTreeMap::new();
    let all = view::load(pool, None, now).await?;
    for c in all.iter().filter(|c| c.verdict.is_update()) {
        if let Some(k) = &c.key {
            stale.entry(k.clone()).or_default().push(c);
        }
    }
    let mut sent = 0;
    for (key, containers) in stale {
        let Some(check) = stand.get(&key) else {
            continue;
        };
        let fixed = check.registry_digest.is_none();
        let fp = fingerprint(
            check.registry_digest.as_deref(),
            check.newest_patch.as_deref(),
            check.newest_minor.as_deref(),
            check.newest_major.as_deref(),
        );
        if check.notified_for.as_deref() == Some(fp.as_str()) {
            continue;
        }
        let mut hosts: Vec<&str> = containers.iter().map(|c| c.host_name.as_str()).collect();
        hosts.sort_unstable();
        hosts.dedup();
        // Bei festen Versionen die höchste angebotene Version nennen.
        let newer = fixed
            .then(|| {
                check
                    .newest_major
                    .clone()
                    .or_else(|| check.newest_minor.clone())
                    .or_else(|| check.newest_patch.clone())
            })
            .flatten();
        let mut tx = pool.begin().await?;
        sqlx::query("INSERT INTO events (kind, payload) VALUES ('image_update', $1)")
            .bind(json!({
                "image": containers[0].image,
                "containers": containers.len(),
                "hosts_count": hosts.len(),
                "hosts": hosts.iter().take(5).collect::<Vec<_>>(),
                "newer": newer,
            }))
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "UPDATE container_image_checks SET notified_for = $4 \
             WHERE registry = $1 AND repository = $2 AND tag = $3 AND platform = ''",
        )
        .bind(&key.0)
        .bind(&key.1)
        .bind(&key.2)
        .bind(&fp)
        .execute(&mut *tx)
        .await?;
        sqlx::query("SELECT pg_notify('pw_events', '')")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        sent += 1;
    }
    Ok(sent)
}
