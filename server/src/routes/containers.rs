//! Docker-Container und Image-Versionen (nur Anzeige). Prüfungen bei den Registries macht der Worker im Hintergrund;
//! der Knopf „Jetzt prüfen“ stößt sie nur früher an. Es wird nie ein Image gezogen oder ein Container verändert.
use crate::authz;
use crate::containers::eval::Verdict;
use crate::containers::view::{self, ContainerView};
use crate::containers::worker::{self, Facts, Key};
use crate::error::{ApiError, ApiResult};
use crate::extract::{Authed, CsrfAuthed};
use crate::schedule;
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::Json;
use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

/// Mindestabstand zwischen zwei manuellen Prüfungen derselben Referenz.
const MIN_RECHECK: Duration = Duration::minutes(5);

/// Container eines Hosts mit Bewertung. Ohne aktivierte Docker-Erfassung (`docker: null`) gibt es keine Container.
pub async fn host_containers(
    _: Authed<authz::p::ContainersRead>,
    State(st): State<AppState>,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    type Head = (
        Option<String>,
        Option<String>,
        Option<chrono::DateTime<Utc>>,
    );
    let head: Option<Head> = sqlx::query_as(
        "SELECT docker_state, docker_reason, docker_checked_at FROM hosts WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&st.pool)
    .await?;
    let (state, reason, checked) = head.ok_or(ApiError::NotFound)?;
    let items = view::load(&st.pool, Some(id), Utc::now()).await?;
    let outdated = items.iter().filter(|c| c.verdict.is_update()).count();
    Ok(Json(json!({
        "docker": state.map(|s| json!({"state": s, "reason": reason, "checked_at": checked})),
        "items": items,
        "outdated": outdated,
    })))
}

#[derive(Deserialize)]
pub struct OverviewQuery {
    q: Option<String>,
    /// `1` = nur Images mit neuerem Stand.
    update: Option<u8>,
    limit: Option<usize>,
    offset: Option<usize>,
}

/// Container über alle Hosts, nach Image gruppiert (Updates zuerst).
pub async fn overview(
    _: Authed<authz::p::ContainersRead>,
    State(st): State<AppState>,
    Query(q): Query<OverviewQuery>,
) -> ApiResult<Json<Value>> {
    let all = view::load(&st.pool, None, Utc::now()).await?;
    let needle =
        q.q.as_deref()
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(str::to_lowercase);
    let mut groups: BTreeMap<String, Vec<&ContainerView>> = BTreeMap::new();
    for c in &all {
        let hit = needle.as_ref().is_none_or(|n| {
            [&c.image, &c.name, &c.host_name]
                .iter()
                .any(|f| f.to_lowercase().contains(n))
        });
        if hit {
            groups.entry(c.image.clone()).or_default().push(c);
        }
    }
    let mut items: Vec<Value> = groups
        .into_iter()
        .map(|(image, cs)| {
            let updates = cs.iter().filter(|c| c.verdict.is_update()).count();
            // Aussage des Images: der erste Container mit Update, sonst der erste.
            let lead = cs.iter().find(|c| c.verdict.is_update()).unwrap_or(&cs[0]);
            let hosts: BTreeSet<i64> = cs.iter().map(|c| c.host_id).collect();
            json!({
                "image": image,
                "verdict": lead.verdict,
                "checked_at": lead.checked_at,
                "updates": updates,
                "hosts": hosts.len(),
                "containers": cs,
            })
        })
        .collect();
    if q.update == Some(1) {
        items.retain(|i| i["updates"].as_u64().unwrap_or(0) > 0);
    }
    // Updates zuerst, dann nach Image (die Gruppierung liefert schon Bildnamen in Reihenfolge).
    items.sort_by_key(|i| std::cmp::Reverse(i["updates"].as_u64().unwrap_or(0)));
    let total = items.len();
    let outdated = items
        .iter()
        .filter(|i| i["updates"].as_u64().unwrap_or(0) > 0)
        .count();
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let items: Vec<Value> = items
        .into_iter()
        .skip(q.offset.unwrap_or(0))
        .take(limit)
        .collect();
    Ok(Json(
        json!({ "items": items, "total": total, "outdated_images": outdated }),
    ))
}

#[derive(Deserialize)]
pub struct CheckBody {
    /// Nur die Images eines Hosts; ohne Angabe alle.
    host_id: Option<i64>,
}

/// Stößt die Prüfung der Image-Versionen jetzt an („angestoßen“; das Ergebnis kommt später). Je Referenz frühestens
/// alle 5 Minuten, insgesamt höchstens 6 Anstöße je Minute und Konto.
pub async fn check(
    CsrfAuthed(admin, _): CsrfAuthed<authz::p::ContainersCheck>,
    State(st): State<AppState>,
    Json(body): Json<CheckBody>,
) -> ApiResult<Json<Value>> {
    st.limiter
        .check(
            &format!("containers-check:{}", admin.username.to_lowercase()),
            6,
            std::time::Duration::from_secs(60),
        )
        .map_err(|w| ApiError::TooManyRequests {
            retry_after_secs: w.as_secs().max(1),
        })?;
    let now = Utc::now();
    let all = view::load(&st.pool, body.host_id, now).await?;
    let facts = Facts::load(&st.pool).await?;
    let mut force: BTreeSet<Key> = BTreeSet::new();
    let mut recent = 0usize;
    for c in &all {
        let Some(key) = &c.key else { continue };
        if matches!(
            c.verdict,
            Verdict::Pinned | Verdict::Unsupported | Verdict::Incomparable
        ) {
            continue;
        }
        if facts
            .base(key)
            .is_some_and(|(_, at)| at + MIN_RECHECK > now)
        {
            if !force.contains(key) {
                recent += 1;
            }
            continue;
        }
        force.insert(key.clone());
    }
    let started = force.len();
    if started > 0 {
        let pool = st.pool.clone();
        let regs = st.registries.clone();
        tokio::spawn(async move {
            let hours = schedule::container_interval_hours(&pool).await;
            if let Err(e) = worker::run_due(
                &pool,
                &regs,
                Utc::now(),
                Duration::hours(hours),
                Some(&force),
            )
            .await
            {
                tracing::warn!(error = %e, "Manuelle Image-Prüfung fehlgeschlagen");
            }
        });
    }
    Ok(Json(
        json!({ "started": started, "skipped_recent": recent }),
    ))
}
