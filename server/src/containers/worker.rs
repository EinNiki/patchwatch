//! Registry-Prüfung im Hintergrund: ein Abruf je (Registry, Repository, Tag) für alle Hosts, Zwischenspeicher in
//! `container_image_checks`, Fehler mit Wartezeit, Abruflimit für Docker Hub. Es wird nie ein Image gezogen.
use super::eval::{Base, PlatformFacts};
use super::reference;
use super::registry::{RegError, Registries, Session};
use super::tags::{self, Kind, Newest};
use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;
use std::collections::{BTreeMap, BTreeSet};

/// Standard-Intervall der Prüfung in Stunden (einstellbar unter Einstellungen → Zeitpläne).
pub const DEFAULT_INTERVAL_HOURS: i64 = 6;
/// Nach einem Fehler wird frühestens nach so langer Zeit erneut gefragt (höchstens das Intervall).
const ERROR_RETRY: Duration = Duration::minutes(30);
/// Eine wegen des Limits verschobene Prüfung wird nach dieser Zeit erneut versucht.
const DEFERRED_RETRY: Duration = Duration::minutes(10);
/// Docker Hub: anonym 100 Pulls je 6 Stunden und IP-Adresse. Wir nutzen höchstens 60 davon (siehe `registry.rs`).
pub const DOCKER_HUB_GET_BUDGET: i64 = 60;
const DOCKER_HUB_WINDOW: Duration = Duration::hours(6);
/// Mehr als diese `GET`-Anfragen braucht eine Prüfung höchstens (Token, Tag-Listen-Seiten, Index, Manifest).
const WORST_CASE_GETS: i64 = 8;
/// Container, die so lange nicht gemeldet wurden, werden nicht mehr geprüft.
pub const VISIBLE_DAYS: i64 = 7;

/// Was der Lauf getan hat (für Tests und das Protokoll).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub checked: u32,
    pub failed: u32,
    pub deferred: u32,
    pub skipped_fresh: u32,
}

#[derive(sqlx::FromRow)]
struct Wanted {
    image_ref: String,
    repo_digests: Vec<String>,
    os: Option<String>,
    arch: Option<String>,
    variant: Option<String>,
}

type Key = (String, String, String);

/// Alle zu prüfenden Tags der sichtbaren Container (nach Registry, Repository, Tag gruppiert).
/// Je Schlüssel die Container (mit Plattform und lokalen Digests), die diese Prüfung braucht.
async fn wanted(pool: &PgPool, now: DateTime<Utc>) -> sqlx::Result<BTreeMap<Key, Vec<Wanted>>> {
    let rows: Vec<Wanted> = sqlx::query_as(
        "SELECT DISTINCT image_ref, repo_digests, os, arch, variant FROM host_containers \
         WHERE last_seen > $1 AND image_ref <> ''",
    )
    .bind(now - Duration::days(VISIBLE_DAYS))
    .fetch_all(pool)
    .await?;
    let mut jobs: BTreeMap<Key, Vec<Wanted>> = BTreeMap::new();
    for w in rows {
        let Some(r) = reference::parse(&w.image_ref) else {
            continue;
        };
        // Mit Digest festgelegt, unbekannte Registry oder nicht vergleichbarer Tag: keine Anfrage.
        let Some(tag) = r.tag.clone() else { continue };
        if !r.supported() || tags::classify(&tag) == Kind::Incomparable {
            continue;
        }
        let key = (r.registry.clone(), r.repository.clone(), tag);
        jobs.entry(key).or_default().push(w);
    }
    Ok(jobs)
}

#[derive(sqlx::FromRow)]
struct CheckRow {
    checked_at: DateTime<Utc>,
    status: String,
}

fn due(row: Option<&CheckRow>, now: DateTime<Utc>, interval: Duration) -> bool {
    let Some(r) = row else { return true };
    let wait = match r.status.as_str() {
        "error" => ERROR_RETRY.min(interval),
        "deferred" => DEFERRED_RETRY.min(interval),
        _ => interval,
    };
    r.checked_at + wait <= now
}

/// Verbrauch an zählenden Anfragen bei Docker Hub im aktuellen Fenster.
async fn hub_gets_used(pool: &PgPool, now: DateTime<Utc>) -> sqlx::Result<i64> {
    sqlx::query_scalar(
        "SELECT COALESCE(sum(get_count), 0)::bigint FROM container_image_checks WHERE registry = 'docker.io' AND checked_at > $1",
    )
    .bind(now - DOCKER_HUB_WINDOW)
    .fetch_one(pool)
    .await
}

#[allow(clippy::too_many_arguments)]
async fn store_base(
    pool: &PgPool,
    key: &Key,
    now: DateTime<Utc>,
    status: &str,
    error: Option<&str>,
    digest: Option<&str>,
    kind: Option<&str>,
    newest: &Newest,
    incomplete: bool,
    gets: u32,
) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO container_image_checks (registry, repository, tag, platform, checked_at, status, registry_digest, \
            manifest_kind, newest_patch, newest_minor, newest_major, tags_incomplete, get_count, error) \
         VALUES ($1, $2, $3, '', $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) \
         ON CONFLICT (registry, repository, tag, platform) DO UPDATE SET checked_at = EXCLUDED.checked_at, \
            status = EXCLUDED.status, registry_digest = EXCLUDED.registry_digest, manifest_kind = EXCLUDED.manifest_kind, \
            newest_patch = EXCLUDED.newest_patch, newest_minor = EXCLUDED.newest_minor, newest_major = EXCLUDED.newest_major, \
            tags_incomplete = EXCLUDED.tags_incomplete, get_count = EXCLUDED.get_count, error = EXCLUDED.error",
    )
    .bind(&key.0)
    .bind(&key.1)
    .bind(&key.2)
    .bind(now)
    .bind(status)
    .bind(digest)
    .bind(kind)
    .bind(&newest.patch)
    .bind(&newest.minor)
    .bind(&newest.major)
    .bind(incomplete)
    .bind(gets as i32)
    .bind(error)
    .execute(pool)
    .await?;
    Ok(())
}

/// Ergebnis der Plattform-Abfrage (Konfigurations- und Manifest-Digest oder Fehlertext).
struct PlatformResult<'a> {
    status: &'a str,
    config: Option<&'a str>,
    manifest: Option<&'a str>,
    error: Option<&'a str>,
}

async fn store_platform(
    pool: &PgPool,
    key: &Key,
    platform: &str,
    now: DateTime<Utc>,
    r: PlatformResult<'_>,
) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO container_image_checks (registry, repository, tag, platform, checked_at, status, platform_digest, \
            platform_config_digest, error) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
         ON CONFLICT (registry, repository, tag, platform) DO UPDATE SET checked_at = EXCLUDED.checked_at, \
            status = EXCLUDED.status, platform_digest = EXCLUDED.platform_digest, \
            platform_config_digest = EXCLUDED.platform_config_digest, error = EXCLUDED.error",
    )
    .bind(&key.0)
    .bind(&key.1)
    .bind(&key.2)
    .bind(platform)
    .bind(now)
    .bind(r.status)
    .bind(r.manifest)
    .bind(r.config)
    .bind(r.error)
    .execute(pool)
    .await?;
    Ok(())
}

/// Prüft einen gleitenden Tag: Digest per `HEAD`; weicht er von einem lokalen Stand ab und ist das Ergebnis ein Index,
/// wird je betroffener Plattform das Manifest verglichen.
async fn check_floating(
    pool: &PgPool,
    s: &mut Session,
    key: &Key,
    containers: &[Wanted],
    now: DateTime<Utc>,
) -> Result<(), RegError> {
    let head = s.head_manifest(&key.2).await?;
    let mut platforms: BTreeSet<(String, String, Option<String>)> = BTreeSet::new();
    if head.kind == "index" {
        for c in containers {
            let differs = !c.repo_digests.is_empty()
                && !c
                    .repo_digests
                    .iter()
                    .any(|d| d.rsplit_once('@').is_some_and(|(_, x)| x == head.digest));
            if let (true, Some(os), Some(arch)) = (differs, c.os.as_deref(), c.arch.as_deref()) {
                platforms.insert((
                    os.to_owned(),
                    arch.to_owned(),
                    c.variant.clone().filter(|v| !v.is_empty()),
                ));
            }
        }
    }
    for (os, arch, variant) in platforms {
        let name =
            reference::platform(Some(&os), Some(&arch), variant.as_deref()).unwrap_or_default();
        let found = s
            .platform_config(&head.digest, &os, &arch, variant.as_deref())
            .await;
        let err_text = found.as_ref().err().map(RegError::text).unwrap_or_default();
        let result = match &found {
            Ok(Some(p)) => PlatformResult {
                status: "ok",
                config: Some(&p.config_digest),
                manifest: Some(&p.manifest_digest),
                error: None,
            },
            Ok(None) => PlatformResult {
                status: "error",
                config: None,
                manifest: None,
                error: Some("Plattform im Index der Registry nicht gefunden"),
            },
            Err(_) => PlatformResult {
                status: "error",
                config: None,
                manifest: None,
                error: Some(&err_text),
            },
        };
        store_platform(pool, key, &name, now, result)
            .await
            .map_err(|_| RegError::Network)?;
    }
    store_base(
        pool,
        key,
        now,
        "ok",
        None,
        Some(&head.digest),
        Some(head.kind),
        &Newest::default(),
        false,
        s.gets,
    )
    .await
    .map_err(|_| RegError::Network)
}

/// Prüft eine feste Version: Tag-Liste und der Vergleich nach Patch, Minor und Major.
async fn check_fixed(
    pool: &PgPool,
    s: &mut Session,
    key: &Key,
    now: DateTime<Utc>,
) -> Result<(), RegError> {
    let Kind::Fixed(current) = tags::classify(&key.2) else {
        return Err(RegError::Format);
    };
    let (all, incomplete) = s.list_tags().await?;
    let newest = tags::newest(&current, &all);
    store_base(
        pool, key, now, "ok", None, None, None, &newest, incomplete, s.gets,
    )
    .await
    .map_err(|_| RegError::Network)
}

/// Prüft alle fälligen Tags. `force`: Zeitstempel ignorieren (Knopf „Jetzt prüfen“; der Mindestabstand wird vorher geprüft).
pub async fn run_due(
    pool: &PgPool,
    regs: &Registries,
    now: DateTime<Utc>,
    interval: Duration,
    force: Option<&BTreeSet<Key>>,
) -> sqlx::Result<Summary> {
    let jobs = wanted(pool, now).await?;
    let mut sum = Summary::default();
    // Docker Hub: Verbrauch einmal lesen und dann selbst mitzählen (die Zeilen entstehen erst beim Speichern).
    let mut hub_used = hub_gets_used(pool, now).await?;
    // Registries, die in diesem Lauf drosseln: der Rest dieser Registry wartet bis zum nächsten Lauf.
    let mut throttled: BTreeSet<String> = BTreeSet::new();
    for (key, containers) in &jobs {
        let row: Option<CheckRow> = sqlx::query_as(
            "SELECT checked_at, status FROM container_image_checks WHERE registry = $1 AND repository = $2 AND tag = $3 AND platform = ''",
        )
        .bind(&key.0)
        .bind(&key.1)
        .bind(&key.2)
        .fetch_optional(pool)
        .await?;
        let forced = force.is_some_and(|f| f.contains(key));
        if !forced && !due(row.as_ref(), now, interval) {
            sum.skipped_fresh += 1;
            continue;
        }
        if throttled.contains(&key.0) {
            continue;
        }
        if key.0 == "docker.io" && hub_used + WORST_CASE_GETS > DOCKER_HUB_GET_BUDGET {
            sum.deferred += 1;
            // Ein vorhandener Stand bleibt stehen; ohne Stand wird „später geprüft“ vermerkt.
            if row.is_none() {
                store_base(
                    pool,
                    key,
                    now,
                    "deferred",
                    None,
                    None,
                    None,
                    &Newest::default(),
                    false,
                    0,
                )
                .await?;
            }
            continue;
        }
        let outcome = match regs.session(&key.0, &key.1).await {
            Err(e) => Err((e, 0)),
            Ok(mut s) => {
                let r = match tags::classify(&key.2) {
                    Kind::Fixed(_) => check_fixed(pool, &mut s, key, now).await,
                    _ => check_floating(pool, &mut s, key, containers, now).await,
                };
                let gets = s.gets;
                r.map(|()| gets).map_err(|e| (e, gets))
            }
        };
        match outcome {
            Ok(gets) => {
                sum.checked += 1;
                if key.0 == "docker.io" {
                    hub_used += i64::from(gets);
                }
            }
            Err((e, gets)) => {
                sum.failed += 1;
                if key.0 == "docker.io" {
                    hub_used += i64::from(gets);
                }
                if matches!(e, RegError::Throttled { .. }) {
                    throttled.insert(key.0.clone());
                }
                store_base(
                    pool,
                    key,
                    now,
                    "error",
                    Some(&e.text()),
                    None,
                    None,
                    &Newest::default(),
                    false,
                    gets,
                )
                .await?;
            }
        }
    }
    Ok(sum)
}

/// Lädt die gespeicherten Tatsachen zu einem Tag (für die Bewertung).
pub async fn load_facts(
    pool: &PgPool,
    key: &Key,
    platform: Option<&str>,
) -> sqlx::Result<(Option<Base>, Option<PlatformFacts>)> {
    #[derive(sqlx::FromRow)]
    struct Row {
        status: String,
        error: Option<String>,
        registry_digest: Option<String>,
        manifest_kind: Option<String>,
        newest_patch: Option<String>,
        newest_minor: Option<String>,
        newest_major: Option<String>,
        tags_incomplete: bool,
        platform_config_digest: Option<String>,
    }
    let q = "SELECT status, error, registry_digest, manifest_kind, newest_patch, newest_minor, newest_major, tags_incomplete, \
             platform_config_digest FROM container_image_checks WHERE registry = $1 AND repository = $2 AND tag = $3 AND platform = $4";
    let base: Option<Row> = sqlx::query_as(q)
        .bind(&key.0)
        .bind(&key.1)
        .bind(&key.2)
        .bind("")
        .fetch_optional(pool)
        .await?;
    let plat: Option<Row> = match platform {
        Some(p) => {
            sqlx::query_as(q)
                .bind(&key.0)
                .bind(&key.1)
                .bind(&key.2)
                .bind(p)
                .fetch_optional(pool)
                .await?
        }
        None => None,
    };
    Ok((
        base.map(|r| Base {
            status: r.status,
            error: r.error,
            registry_digest: r.registry_digest,
            manifest_kind: r.manifest_kind,
            newest: Newest {
                patch: r.newest_patch,
                minor: r.newest_minor,
                major: r.newest_major,
            },
            tags_incomplete: r.tags_incomplete,
        }),
        plat.map(|r| PlatformFacts {
            status: r.status,
            config_digest: r.platform_config_digest,
        }),
    ))
}
