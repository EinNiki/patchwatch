//! Annahme und Speicherung des Docker-Blocks eines Reports. Der Block kommt von einem Agent und wird wie jede Eingabe
//! behandelt: feste Zeichensätze und Längen, fremde Felder werden beim Einlesen verworfen (kein `flatten`).
use crate::error::{ApiError, ApiResult};
use chrono::{DateTime, TimeZone, Utc};
use serde::Deserialize;

/// Mehr Container nimmt der Server nicht an (der Agent kappt bei derselben Zahl).
pub const MAX_CONTAINERS: usize = 500;
const MAX_DIGESTS: usize = 8;
const STATES: [&str; 8] = [
    "running",
    "exited",
    "created",
    "paused",
    "restarting",
    "dead",
    "removing",
    "unknown",
];
const REASONS: [&str; 4] = ["socket_missing", "no_permission", "timeout", "bad_response"];

#[derive(Deserialize)]
pub struct DockerIn {
    state: String,
    reason: Option<String>,
    #[serde(default)]
    containers: Vec<ContainerIn>,
}

#[derive(Deserialize)]
struct ContainerIn {
    id: String,
    name: String,
    state: String,
    #[serde(default)]
    created_unix: u64,
    #[serde(default)]
    status_text: String,
    #[serde(default)]
    image: String,
    #[serde(default)]
    image_id: String,
    #[serde(default)]
    repo_digests: Vec<String>,
    os: Option<String>,
    arch: Option<String>,
    variant: Option<String>,
    compose_project: Option<String>,
    compose_service: Option<String>,
}

fn bad(what: &str) -> ApiError {
    ApiError::BadRequest(format!("ungültiger Wert für docker.{what}"))
}

fn chars_ok(s: &str, max: usize, extra: &str) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || extra.contains(c))
}

fn is_digest(d: &str) -> bool {
    d.strip_prefix("sha256:")
        .is_some_and(|h| h.len() == 64 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

/// Docker-Dienstname (Compose): `^[A-Za-z0-9._-]{1,64}$`. Auch von der Oberfläche vor dem Anzeigen des Befehls geprüft.
pub fn valid_compose_name(s: &str) -> bool {
    chars_ok(s, 64, "._-")
}

pub fn validate(d: &DockerIn) -> ApiResult<()> {
    match (d.state.as_str(), d.reason.as_deref()) {
        ("ok", None) => {}
        ("unavailable", Some(r)) if REASONS.contains(&r) => {}
        _ => return Err(bad("state")),
    }
    if d.containers.len() > MAX_CONTAINERS {
        return Err(bad("containers"));
    }
    for c in &d.containers {
        let hex12 =
            c.id.len() == 12 && c.id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        if !hex12 {
            return Err(bad("id"));
        }
        if !chars_ok(&c.name, 128, "._-")
            || !c.name.starts_with(|ch: char| ch.is_ascii_alphanumeric())
        {
            return Err(bad("name"));
        }
        if !STATES.contains(&c.state.as_str()) {
            return Err(bad("state"));
        }
        if c.status_text.len() > 64
            || c.status_text
                .chars()
                .any(|ch| !(ch.is_ascii_alphanumeric() || " ().,:-".contains(ch)))
        {
            return Err(bad("status_text"));
        }
        // Leer ist erlaubt (Agent konnte die Angabe nicht lesen); sonst nur Referenzzeichen.
        if !c.image.is_empty() && !chars_ok(&c.image, 255, ".:/@_-") {
            return Err(bad("image"));
        }
        if !c.image_id.is_empty() && !is_digest(&c.image_id) {
            return Err(bad("image_id"));
        }
        if c.repo_digests.len() > MAX_DIGESTS
            || c.repo_digests.iter().any(|r| {
                !r.rsplit_once('@')
                    .is_some_and(|(repo, d)| chars_ok(repo, 255, "./:_-") && is_digest(d))
            })
        {
            return Err(bad("repo_digests"));
        }
        for (v, what) in [(&c.os, "os"), (&c.arch, "arch"), (&c.variant, "variant")] {
            if v.as_deref().is_some_and(|s| !chars_ok(s, 32, "._-")) {
                return Err(bad(what));
            }
        }
        for (v, what) in [
            (&c.compose_project, "compose_project"),
            (&c.compose_service, "compose_service"),
        ] {
            if v.as_deref().is_some_and(|s| !valid_compose_name(s)) {
                return Err(bad(what));
            }
        }
        if i64::try_from(c.created_unix).is_err() || c.created_unix > 4_102_444_800 {
            return Err(bad("created_unix"));
        }
    }
    Ok(())
}

fn at(unix: u64) -> Option<DateTime<Utc>> {
    (unix > 0)
        .then(|| Utc.timestamp_opt(unix as i64, 0).single())
        .flatten()
}

/// Speichert den Docker-Block. Ohne Block (Docker aus oder älterer Agent) wird der Zustand auf „nicht aktiviert“ gesetzt;
/// vorhandene Container bleiben liegen und verschwinden nach 7 Tagen aus den Abfragen. Bei `unavailable` bleibt die
/// letzte Containerliste stehen (der Grund wird angezeigt).
pub async fn store(
    tx: &mut sqlx::PgConnection,
    host_id: i64,
    docker: Option<&DockerIn>,
    now: DateTime<Utc>,
) -> ApiResult<()> {
    let Some(d) = docker else {
        sqlx::query("UPDATE hosts SET docker_state = NULL, docker_reason = NULL WHERE id = $1")
            .bind(host_id)
            .execute(&mut *tx)
            .await?;
        return Ok(());
    };
    sqlx::query("UPDATE hosts SET docker_state = $2, docker_reason = $3, docker_checked_at = $4 WHERE id = $1")
        .bind(host_id)
        .bind(&d.state)
        .bind(&d.reason)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    if d.state != "ok" || d.containers.is_empty() {
        return Ok(());
    }
    // Eine ID höchstens einmal (sonst Fehler 21000 beim Upsert): der erste Eintrag gilt.
    let mut seen = std::collections::HashSet::new();
    let list: Vec<&ContainerIn> = d
        .containers
        .iter()
        .filter(|c| seen.insert(c.id.as_str()))
        .collect();
    let col = |f: fn(&ContainerIn) -> Option<&str>| {
        list.iter()
            .map(|c| f(c).map(str::to_owned))
            .collect::<Vec<_>>()
    };
    sqlx::query(
        "INSERT INTO host_containers (host_id, container_id, name, state, created_at, status_text, image_ref, image_id, \
                repo_digests, os, arch, variant, compose_project, compose_service, first_seen, last_seen) \
         SELECT $1, i, n, s, cr, st, im, iid, string_to_array(rd, ' '), o, a, v, cp, cs, $15, $15 \
         FROM UNNEST($2::text[], $3::text[], $4::text[], $5::timestamptz[], $6::text[], $7::text[], $8::text[], \
                     $9::text[], $10::text[], $11::text[], $12::text[], $13::text[], $14::text[]) \
              AS t(i, n, s, cr, st, im, iid, rd, o, a, v, cp, cs) \
         ON CONFLICT (host_id, container_id) DO UPDATE SET name = EXCLUDED.name, state = EXCLUDED.state, \
              created_at = EXCLUDED.created_at, status_text = EXCLUDED.status_text, image_ref = EXCLUDED.image_ref, \
              image_id = EXCLUDED.image_id, repo_digests = EXCLUDED.repo_digests, os = EXCLUDED.os, arch = EXCLUDED.arch, \
              variant = EXCLUDED.variant, compose_project = EXCLUDED.compose_project, \
              compose_service = EXCLUDED.compose_service, last_seen = EXCLUDED.last_seen",
    )
    .bind(host_id)
    .bind(list.iter().map(|c| c.id.clone()).collect::<Vec<_>>())
    .bind(list.iter().map(|c| c.name.clone()).collect::<Vec<_>>())
    .bind(list.iter().map(|c| c.state.clone()).collect::<Vec<_>>())
    .bind(list.iter().map(|c| at(c.created_unix)).collect::<Vec<_>>())
    .bind(list.iter().map(|c| c.status_text.clone()).collect::<Vec<_>>())
    .bind(list.iter().map(|c| c.image.clone()).collect::<Vec<_>>())
    .bind(list.iter().map(|c| c.image_id.clone()).collect::<Vec<_>>())
    // Digests als ein Text je Container (durch Leerzeichen getrennt; Digest-Zeichen enthalten keine), unten wieder geteilt.
    .bind(list.iter().map(|c| c.repo_digests.join(" ")).collect::<Vec<_>>())
    .bind(col(|c| c.os.as_deref()))
    .bind(col(|c| c.arch.as_deref()))
    .bind(col(|c| c.variant.as_deref()))
    .bind(col(|c| c.compose_project.as_deref()))
    .bind(col(|c| c.compose_service.as_deref()))
    .bind(now)
    .execute(&mut *tx)
    .await?;
    Ok(())
}
