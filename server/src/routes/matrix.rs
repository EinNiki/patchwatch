use crate::cve::reeval;
use crate::error::{ApiError, ApiResult};
use crate::extract::Admin;
use crate::routes::cves::valid_cve_id;
use crate::state::AppState;
use axum::extract::{Query, State};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

type Known = (String, String, DateTime<Utc>, Value);

const MAX_HOSTS: usize = 500;
const MAX_CVES: usize = 200;

#[derive(Deserialize)]
pub struct MatrixQuery {
    /// Kommagetrennte CVE-IDs; ohne Angabe die Watchlist.
    cves: Option<String>,
    /// Kommagetrennte Host-IDs; ohne Angabe alle Hosts.
    hosts: Option<String>,
}

#[derive(Serialize)]
struct Cell {
    host_id: i64,
    cve_id: String,
    status: String,
    reason: String,
    computed_at: Option<DateTime<Utc>>,
    sources: Value,
    /// `true`, wenn die Zelle ad hoc berechnet wurde (noch kein gespeicherter Status).
    live: bool,
    /// Manuelle Prüfung für den aktuellen Kernel des Hosts.
    manual_review: Option<Value>,
}

/// Zellen für die Matrix-Ansicht. Fehlende Bewertungen werden als `unknown` geliefert, nie als grün.
pub async fn matrix(
    _: Admin,
    State(st): State<AppState>,
    Query(q): Query<MatrixQuery>,
) -> ApiResult<Json<Value>> {
    let cve_ids: Vec<String> = match q.cves.as_deref().filter(|s| !s.is_empty()) {
        Some(s) => s.split(',').map(|x| x.trim().to_owned()).collect(),
        None => {
            sqlx::query_scalar("SELECT cve_id FROM cve_watchlist ORDER BY cve_id")
                .fetch_all(&st.pool)
                .await?
        }
    };
    if cve_ids.len() > MAX_CVES || !cve_ids.iter().all(|c| valid_cve_id(c)) {
        return Err(ApiError::BadRequest(format!(
            "cves: höchstens {MAX_CVES} gültige CVE-IDs"
        )));
    }
    let host_filter: Option<Vec<i64>> = match q.hosts.as_deref().filter(|s| !s.is_empty()) {
        Some(s) => Some(
            s.split(',')
                .map(|x| x.trim().parse::<i64>())
                .collect::<Result<_, _>>()
                .map_err(|_| {
                    ApiError::BadRequest("hosts: kommagetrennte Zahlen erwartet".into())
                })?,
        ),
        None => None,
    };
    if host_filter.as_ref().is_some_and(|h| h.len() > MAX_HOSTS) {
        return Err(ApiError::BadRequest(format!(
            "hosts: höchstens {MAX_HOSTS}"
        )));
    }

    let hosts: Vec<(i64, String, String)> = sqlx::query_as(
        "SELECT id, name, status FROM hosts WHERE ($1::bigint[] IS NULL OR id = ANY($1)) ORDER BY name LIMIT 500",
    )
    .bind(&host_filter)
    .fetch_all(&st.pool)
    .await?;
    let host_ids: Vec<i64> = hosts.iter().map(|h| h.0).collect();

    let rows: Vec<(i64, String, String, String, DateTime<Utc>, Value)> = sqlx::query_as(
        "SELECT host_id, cve_id, status, reason, computed_at, sources FROM host_cve_status \
         WHERE host_id = ANY($1) AND cve_id = ANY($2)",
    )
    .bind(&host_ids)
    .bind(&cve_ids)
    .fetch_all(&st.pool)
    .await?;
    let mut known: HashMap<(i64, String), Known> = rows
        .into_iter()
        .map(|(h, c, s, r, t, src)| ((h, c), (s, r, t, src)))
        .collect();

    // Nicht gespeicherte Zellen (CVE ohne Handlungsbezug, z. B. "behoben") live berechnen.
    let missing_hosts: Vec<i64> = host_ids
        .iter()
        .copied()
        .filter(|h| {
            cve_ids
                .iter()
                .any(|c| !known.contains_key(&(*h, c.clone())))
        })
        .collect();
    let live = reeval::evaluate_live(&st.pool, &missing_hosts, &cve_ids).await?;

    // Manuelle Prüfungen gelten nur, solange der Host denselben Kernel läuft.
    let reviews: Vec<(i64, String, DateTime<Utc>, String)> = sqlx::query_as(
        "SELECT m.host_id, m.cve_id, m.reviewed_at, m.reviewed_by FROM manual_reviews m \
         JOIN hosts h ON h.id = m.host_id AND h.running_kernel = m.kernel_version \
         WHERE m.host_id = ANY($1) AND m.cve_id = ANY($2)",
    )
    .bind(&host_ids)
    .bind(&cve_ids)
    .fetch_all(&st.pool)
    .await?;
    let reviews: HashMap<(i64, String), Value> = reviews
        .into_iter()
        .map(|(h, c, at, by)| {
            (
                (h, c),
                serde_json::json!({ "reviewed_at": at, "reviewed_by": by }),
            )
        })
        .collect();

    let now = Utc::now();
    let mut cells = Vec::with_capacity(hosts.len() * cve_ids.len());
    for (hid, _, _) in &hosts {
        for cve in &cve_ids {
            let key = (*hid, cve.clone());
            let manual_review = reviews.get(&key).cloned();
            let cell = if let Some((status, reason, at, sources)) = known.remove(&key) {
                Cell {
                    host_id: *hid,
                    cve_id: cve.clone(),
                    status,
                    reason,
                    computed_at: Some(at),
                    sources,
                    live: false,
                    manual_review,
                }
            } else if let Some(v) = live.get(&key) {
                Cell {
                    host_id: *hid,
                    cve_id: cve.clone(),
                    status: v.status.as_str().into(),
                    reason: v.reason.clone(),
                    computed_at: Some(now),
                    sources: Value::Array(v.sources.clone()),
                    live: true,
                    manual_review,
                }
            } else {
                Cell {
                    host_id: *hid,
                    cve_id: cve.clone(),
                    status: "unknown".into(),
                    reason: "Noch nicht bewertet: keine Daten für diesen Host und diese CVE."
                        .into(),
                    computed_at: None,
                    sources: Value::Array(vec![]),
                    live: false,
                    manual_review,
                }
            };
            cells.push(cell);
        }
    }
    let hosts: Vec<Value> = hosts
        .into_iter()
        .map(|(id, name, status)| serde_json::json!({ "id": id, "name": name, "status": status }))
        .collect();
    Ok(Json(
        serde_json::json!({ "hosts": hosts, "cves": cve_ids, "cells": cells }),
    ))
}
