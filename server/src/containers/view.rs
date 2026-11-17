//! Container der Hosts zusammen mit der Bewertung (für die Routen und die Benachrichtigung). Eine Abfrage für die
//! Container und eine für alle gespeicherten Registry-Tatsachen; bewertet wird in `eval`.
use super::eval::{compose_command, evaluate, Local, Verdict};
use super::reference;
use super::worker::{Facts, Key, VISIBLE_DAYS};
use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use sqlx::PgPool;

#[derive(sqlx::FromRow)]
struct Row {
    host_id: i64,
    host_name: String,
    name: String,
    state: String,
    status_text: String,
    created_at: Option<DateTime<Utc>>,
    image_ref: String,
    image_id: String,
    repo_digests: Vec<String>,
    os: Option<String>,
    arch: Option<String>,
    variant: Option<String>,
    compose_project: Option<String>,
    compose_service: Option<String>,
    last_seen: DateTime<Utc>,
}

#[derive(Serialize)]
pub struct ContainerView {
    pub host_id: i64,
    pub host_name: String,
    pub name: String,
    pub state: String,
    pub status_text: String,
    pub created_at: Option<DateTime<Utc>>,
    pub image: String,
    pub compose_project: Option<String>,
    pub compose_service: Option<String>,
    pub last_seen: DateTime<Utc>,
    pub verdict: Verdict,
    /// Wann die Registry zuletzt gefragt wurde (leer, solange noch nie).
    pub checked_at: Option<DateTime<Utc>>,
    /// Nur zum Kopieren; wird nie ausgeführt.
    pub command: Option<String>,
    /// Ausgangspunkt für Gruppierung und Benachrichtigung; nicht Teil der Antwort.
    #[serde(skip)]
    pub key: Option<Key>,
}

/// Sichtbare Container (in den letzten 7 Tagen gemeldet), optional nur eines Hosts, mit Bewertung.
pub async fn load(
    pool: &PgPool,
    host: Option<i64>,
    now: DateTime<Utc>,
) -> sqlx::Result<Vec<ContainerView>> {
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT c.host_id, h.name AS host_name, c.name, c.state, c.status_text, c.created_at, c.image_ref, c.image_id, \
         c.repo_digests, c.os, c.arch, c.variant, c.compose_project, c.compose_service, c.last_seen \
         FROM host_containers c JOIN hosts h ON h.id = c.host_id \
         WHERE c.last_seen > $1 AND h.docker_state = 'ok' AND ($2::bigint IS NULL OR c.host_id = $2) ORDER BY h.name, c.name",
    )
    .bind(now - Duration::days(VISIBLE_DAYS))
    .bind(host)
    .fetch_all(pool)
    .await?;
    let facts = Facts::load(pool).await?;
    Ok(rows
        .into_iter()
        .map(|r| {
            let parsed = reference::parse(&r.image_ref);
            let key = parsed
                .as_ref()
                .filter(|p| p.digest.is_none())
                .and_then(|p| Some((p.registry.clone(), p.repository.clone(), p.tag.clone()?)));
            let platform =
                reference::platform(r.os.as_deref(), r.arch.as_deref(), r.variant.as_deref());
            let base = key.as_ref().and_then(|k| facts.base(k));
            let plat = key
                .as_ref()
                .zip(platform.as_deref())
                .and_then(|(k, p)| facts.platform(k, p));
            let verdict = evaluate(
                &Local {
                    image_ref: &r.image_ref,
                    image_id: &r.image_id,
                    repo_digests: &r.repo_digests,
                },
                base.map(|b| b.0),
                plat,
            );
            let command = verdict
                .is_update()
                .then(|| compose_command(r.compose_service.as_deref()))
                .flatten();
            ContainerView {
                host_id: r.host_id,
                host_name: r.host_name,
                name: r.name,
                state: r.state,
                status_text: r.status_text,
                created_at: r.created_at,
                image: r.image_ref,
                compose_project: r.compose_project,
                compose_service: r.compose_service,
                last_seen: r.last_seen,
                verdict,
                checked_at: base.map(|b| b.1),
                command,
                key,
            }
        })
        .collect())
}
