//! Explicit, bounded OSV lookups; no invented advisories or cross-ecosystem version comparisons.
use crate::cve::http::{self, Limits};
use crate::error::{ApiError, ApiResult};
use crate::{sbom, AppState};
use axum::Json;
use chrono::{DateTime, Duration, Utc};
use packageurl::PackageUrl;
use serde_json::{json, Value};
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration as StdDuration;

pub const FRESH_HOURS: i64 = 24;

/// OSV may report GHSA/RUSTSEC/PYSEC identifiers without a CVE alias.
fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-._".contains(c))
}

type BatchResult = (String, Vec<String>, Option<String>);
pub fn batch_results(body: &Value, requests: &[String]) -> Result<Vec<BatchResult>, String> {
    let results = body
        .get("results")
        .and_then(Value::as_array)
        .ok_or("OSV-Antwort enthält keine Ergebnisliste.")?;
    if results.len() != requests.len() {
        return Err("OSV-Antwort passt nicht zur Abfrage.".into());
    }
    let mut out = Vec::new();
    for (purl, result) in requests.iter().zip(results) {
        if !result.is_object() || result.get("error").is_some() {
            return Err("OSV hat eine unvollständige Antwort geliefert.".into());
        }
        let mut ids = Vec::new();
        if let Some(vulns) = result.get("vulns") {
            for vuln in vulns.as_array().ok_or("OSV-Meldungen sind keine Liste.")? {
                let id = vuln
                    .get("id")
                    .and_then(Value::as_str)
                    .filter(|s| valid_id(s))
                    .ok_or("Ungültige OSV-Meldungskennung.")?;
                ids.push(id.to_owned());
            }
        }
        let token = match result.get("next_page_token") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) if s.is_empty() => None,
            Some(Value::String(s)) if s.len() <= 4096 => Some(s.clone()),
            _ => return Err("Ungültiger OSV-Seitencursor.".into()),
        };
        out.push((purl.clone(), ids, token));
    }
    Ok(out)
}

async fn query(
    client: &reqwest::Client,
    base: &str,
    purls: &[String],
) -> Result<HashMap<String, Value>, String> {
    let mut out = HashMap::new();
    let limits = Limits {
        max_bytes: 4 * 1024 * 1024,
        timeout: StdDuration::from_secs(10),
        attempts: 1,
        base_delay: StdDuration::ZERO,
        retry_after_cap: StdDuration::ZERO,
    };
    for chunk in purls.chunks(100) {
        let mut pending: Vec<(String, Option<String>)> =
            chunk.iter().map(|p| (p.clone(), None)).collect();
        let mut ids: HashMap<String, BTreeSet<String>> = HashMap::new();
        for _ in 0..5 {
            let requests: Vec<String> = pending.iter().map(|(p, _)| p.clone()).collect();
            let payload = json!({"queries":pending.iter().map(|(p,t)| {
                let mut q=json!({"package":{"purl":p}});
                if let Some(t)=t { q["page_token"]=json!(t); }
                q
            }).collect::<Vec<_>>()});
            let response = http::post_json(
                client,
                &format!("{}/v1/querybatch", base.trim_end_matches('/')),
                &payload,
                limits,
            )
            .await
            .map_err(|_| {
                "OSV-Abfrage fehlgeschlagen. Bitte Quelle prüfen und erneut versuchen.".to_owned()
            })?;
            let body: Value = serde_json::from_slice(&response.body)
                .map_err(|_| "OSV hat kein gültiges JSON geliefert.")?;
            pending.clear();
            for (purl, found, token) in batch_results(&body, &requests)? {
                let all = ids.entry(purl.clone()).or_default();
                all.extend(found);
                if all.len() > 10000 {
                    return Err("Zu viele OSV-Meldungen für eine Komponente.".into());
                }
                if let Some(token) = token {
                    pending.push((purl, Some(token)));
                }
            }
            if pending.is_empty() {
                break;
            }
        }
        if !pending.is_empty() {
            return Err("OSV-Seitenlimit erreicht; die Prüfung ist unvollständig.".into());
        }
        for (purl, found) in ids {
            let findings:Vec<Value>=found.into_iter().map(|id|json!({"id":id,"status":"vulnerable","source":"osv",
                "fix_version":null,"reason":"OSV meldet diese Paketversion als betroffen. Details und mögliche Fixes stehen in der Originalmeldung.",
                "url":format!("https://osv.dev/vulnerability/{id}")})).collect();
            out.insert(purl, json!(findings));
        }
    }
    Ok(out)
}

type Source = (String, Option<String>, Option<String>);
type Cached = (Value, DateTime<Utc>);

pub async fn scan(st: &AppState, id: i64) -> ApiResult<Json<Value>> {
    let _slot = st
        .software_scan_slots
        .try_acquire()
        .map_err(|_| ApiError::Conflict("Es laufen bereits zwei Softwareprüfungen.".into()))?;
    let lock = {
        let mut locks = st
            .kind_locks
            .lock()
            .map_err(|_| ApiError::Internal(anyhow::anyhow!("scan lock")))?;
        locks
            .entry(format!("software:{id}"))
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    };
    let _guard = lock
        .try_lock()
        .map_err(|_| ApiError::Conflict("Dieses Inventar wird bereits geprüft.".into()))?;
    st.limiter
        .check(
            &format!("software-scan:{id}"),
            3,
            StdDuration::from_secs(60),
        )
        .map_err(|w| ApiError::TooManyRequests {
            retry_after_secs: w.as_secs().max(1),
        })?;
    let snapshot: Option<(i64, i64)> =
        sqlx::query_as("SELECT host_id,generation FROM software_inventories WHERE id=$1")
            .bind(id)
            .fetch_optional(&st.pool)
            .await?;
    let (host_id, generation) = snapshot.ok_or(ApiError::NotFound)?;
    let source:Option<Source>=sqlx::query_as("SELECT id,base_url,ecosystem FROM cve_sources WHERE kind='osv' AND enabled AND deleted_at IS NULL ORDER BY ecosystem NULLS FIRST,created_at,id LIMIT 1")
        .fetch_optional(&st.pool).await?;
    let (source_id, override_url, scope) = source.ok_or_else(|| {
        ApiError::BadRequest("Aktiviere zuerst eine OSV-Quelle unter CVEs → Quellen.".into())
    })?;
    let (base, client) = if let Some(raw) = &override_url {
        let target = crate::cve::sources::check_base_url(st, raw)
            .await
            .map_err(ApiError::BadRequest)?;
        (
            raw.clone(),
            crate::notify::ssrf::pinned_client(&target)
                .map_err(|_| ApiError::BadRequest("OSV-Client nicht verfügbar.".into()))?,
        )
    } else {
        (st.cfg.cve.osv_url.clone(), st.http.clone())
    };
    let components: Vec<(i64, Option<String>)> =
        sqlx::query_as("SELECT id,purl FROM software_components WHERE inventory_id=$1 ORDER BY id")
            .bind(id)
            .fetch_all(&st.pool)
            .await?;
    let mut eligible = BTreeSet::new();
    for (_, purl) in &components {
        if let Some(raw) = purl {
            if let Ok(p) = raw.parse::<PackageUrl<'static>>() {
                if p.version().is_some()
                    && p.qualifiers().is_empty()
                    && p.subpath().is_none()
                    && sbom::osv_ecosystem(p.ty())
                        .is_some_and(|eco| scope.as_deref().is_none_or(|s| s == eco))
                {
                    eligible.insert(raw.clone());
                }
            }
        }
    }
    if eligible.len() > 2000 {
        return Err(ApiError::BadRequest("Höchstens 2000 unterschiedliche Paketversionen pro Prüfung. Teile größere Inventare auf.".into()));
    }
    let eligible: Vec<String> = eligible.into_iter().collect();
    let cached:Vec<(String,Value,DateTime<Utc>)>=sqlx::query_as("SELECT purl,findings,fetched_at FROM software_osv_cache WHERE source_id=$1 AND endpoint=$2 AND purl=ANY($3) AND fetched_at>now()-interval '24 hours'")
        .bind(&source_id).bind(&base).bind(&eligible).fetch_all(&st.pool).await?;
    let mut checked: HashMap<String, Cached> =
        cached.into_iter().map(|(p, v, t)| (p, (v, t))).collect();
    let missing: Vec<String> = eligible
        .iter()
        .filter(|p| !checked.contains_key(*p))
        .cloned()
        .collect();
    let result = tokio::time::timeout(StdDuration::from_secs(60), query(&client, &base, &missing))
        .await
        .unwrap_or_else(|_| Err("Zeitlimit erreicht; OSV-Prüfung ist unvollständig.".into()));
    let mut tx = st.pool.begin().await?;
    let current: Option<i64> =
        sqlx::query_scalar("SELECT generation FROM software_inventories WHERE id=$1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    if current != Some(generation) {
        return Err(ApiError::Conflict(
            "Das Inventar wurde während der Prüfung ersetzt oder entfernt. Bitte erneut prüfen."
                .into(),
        ));
    }
    let active:Option<Source>=sqlx::query_as("SELECT id,base_url,ecosystem FROM cve_sources WHERE id=$1 AND enabled AND deleted_at IS NULL")
        .bind(&source_id).fetch_optional(&mut *tx).await?;
    if active.as_ref() != Some(&(source_id.clone(), override_url, scope)) {
        return Err(ApiError::Conflict(
            "Die OSV-Quelle wurde während der Prüfung geändert. Bitte erneut prüfen.".into(),
        ));
    }
    let now = Utc::now();
    match result {
        Ok(results) => {
            for (purl, findings) in results {
                sqlx::query("INSERT INTO software_osv_cache(source_id,endpoint,purl,findings,fetched_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT(source_id,endpoint,purl) DO UPDATE SET findings=EXCLUDED.findings,fetched_at=EXCLUDED.fetched_at")
                    .bind(&source_id).bind(&base).bind(&purl).bind(&findings).bind(now).execute(&mut *tx).await?;
                checked.insert(purl, (findings, now));
            }
            for (component_id, purl) in &components {
                let (status, findings, at) = match purl.as_ref().and_then(|p| checked.get(p)) {
                    Some((v, t)) if v.as_array().is_some_and(|a| !a.is_empty()) => {
                        ("vulnerable", v.clone(), Some(*t))
                    }
                    Some((v, t)) => ("no_known_findings", v.clone(), Some(*t)),
                    None => ("unknown", json!([]), None),
                };
                sqlx::query("UPDATE software_components SET assessment=$2,findings=$3,assessed_at=$4 WHERE id=$1")
                    .bind(component_id).bind(status).bind(findings).bind(at).execute(&mut *tx).await?;
            }
            sqlx::query("UPDATE software_inventories SET scanned_at=$2,scan_error=NULL,scan_source_id=$3 WHERE id=$1")
                .bind(id).bind(now).bind(&source_id).execute(&mut *tx).await?;
        }
        Err(message) => {
            sqlx::query("UPDATE software_components SET assessment='unknown',findings='[]'::jsonb WHERE inventory_id=$1 AND assessment<>'vulnerable'")
                .bind(id).execute(&mut *tx).await?;
            sqlx::query("UPDATE software_inventories SET scanned_at=$2,scan_error=$3 WHERE id=$1")
                .bind(id)
                .bind(now)
                .bind(&message)
                .execute(&mut *tx)
                .await?;
            crate::live::notify(&mut tx, "software_inventory", Some(host_id), None).await;
            tx.commit().await?;
            return Ok(Json(json!({"ok":false,"error":message,"checked":0})));
        }
    }
    sqlx::query("DELETE FROM software_osv_cache WHERE fetched_at<now()-interval '7 days'")
        .execute(&mut *tx)
        .await?;
    crate::live::notify(&mut tx, "software_inventory", Some(host_id), None).await;
    tx.commit().await?;
    Ok(Json(
        json!({"ok":true,"checked":eligible.len(),"unmatched":components.len()-components.iter().filter(|(_,p)|p.as_ref().is_some_and(|p|checked.contains_key(p))).count(),"valid_until":checked.values().map(|(_,at)|*at).min().map(|at|at+Duration::hours(FRESH_HOURS))}),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn empty_and_non_cve_results_are_distinct_from_broken_responses() {
        let requests = vec!["pkg:npm/foo@1".into()];
        assert!(
            batch_results(&json!({"results":[{}]}), &requests).unwrap()[0]
                .1
                .is_empty()
        );
        assert_eq!(batch_results(&json!({"results":[{"vulns":[{"id":"GHSA-abcd-1234-abcd"}],"next_page_token":"next"}]}),&requests).unwrap()[0].2.as_deref(),Some("next"));
        for value in [
            json!({}),
            json!({"results":[]}),
            json!({"results":[null]}),
            json!({"results":[{"vulns":false}]}),
            json!({"results":[{"vulns":[{"id":"../unsafe"}]}]}),
        ] {
            assert!(batch_results(&value, &requests).is_err());
        }
    }
}
