use crate::authz;
use crate::error::{ApiError, ApiResult};
use crate::extract::{Authed, ClientIp, CsrfAuthed};
use crate::{sbom, AppState};
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Deserialize)]
pub struct Import {
    pub label: String,
    pub kind: String,
    pub identity: Option<String>,
    pub sbom: Value,
}

#[derive(Deserialize)]
pub struct ListQuery {
    pub host_id: Option<i64>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct InventoryRow {
    pub id: i64,
    pub host_id: i64,
    pub host_name: String,
    pub inventory_key: String,
    pub label: String,
    pub kind: String,
    pub identity: Option<String>,
    pub format: String,
    pub spec_version: String,
    pub generation: i64,
    pub imported_at: DateTime<Utc>,
    pub scanned_at: Option<DateTime<Utc>>,
    pub scan_error: Option<String>,
    pub component_count: i64,
}

pub async fn list(
    user: Authed<authz::p::HostsRead>,
    State(st): State<AppState>,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<Value>> {
    let mut rows: Vec<InventoryRow> = sqlx::query_as(
        "SELECT i.*, h.name AS host_name, (SELECT count(*) FROM software_components c WHERE c.inventory_id=i.id) AS component_count \
         FROM software_inventories i JOIN hosts h ON h.id=i.host_id WHERE ($1::bigint IS NULL OR i.host_id=$1) ORDER BY h.name,i.label,i.id"
    ).bind(q.host_id).fetch_all(&st.pool).await?;
    if !user.0.can(authz::Permission::CvesRead) {
        for row in &mut rows {
            row.scanned_at = None;
            row.scan_error = None;
        }
    }
    let osv_ready: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM cve_sources WHERE kind='osv' AND enabled AND deleted_at IS NULL)")
        .fetch_one(&st.pool).await?;
    Ok(Json(json!({"items": rows, "osv_ready": osv_ready})))
}

pub async fn put(
    _: CsrfAuthed<authz::p::HostsWrite>,
    State(st): State<AppState>,
    Path((host_id, key)): Path<(i64, String)>,
    Json(input): Json<Import>,
) -> ApiResult<Json<Value>> {
    store(&st, host_id, &key, input).await
}

/// CI uploads are bound to the host owning the token; no host ID is accepted in the request.
pub async fn agent_put(
    State(st): State<AppState>,
    ClientIp(ip): ClientIp,
    Path(key): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    let host_id = super::agent::authenticate_host(&st, &ip, &headers, "sbom", 30).await?;
    let input: Import = serde_json::from_slice(&body)
        .map_err(|_| ApiError::BadRequest("Ungültiger SBOM-Import.".into()))?;
    store(&st, host_id, &key, input).await
}

pub async fn store(
    st: &AppState,
    host_id: i64,
    key: &str,
    input: Import,
) -> ApiResult<Json<Value>> {
    if key.is_empty()
        || key.len() > 80
        || !key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
    {
        return Err(ApiError::BadRequest(
            "Inventarschlüssel: 1–80 Buchstaben, Zahlen, Punkte, Unterstriche oder Bindestriche."
                .into(),
        ));
    }
    sbom::text(&input.label, 200).map_err(ApiError::BadRequest)?;
    if let Some(identity) = &input.identity {
        sbom::text(identity, 512).map_err(ApiError::BadRequest)?;
    }
    if !["application", "container", "manual"].contains(&input.kind.as_str()) {
        return Err(ApiError::BadRequest("Unbekannte Inventarart.".into()));
    }
    let parsed = sbom::parse(&input.sbom).map_err(ApiError::BadRequest)?;
    let mut tx = st.pool.begin().await?;
    let exists: Option<i64> = sqlx::query_scalar("SELECT id FROM hosts WHERE id=$1 FOR UPDATE")
        .bind(host_id)
        .fetch_optional(&mut *tx)
        .await?;
    if exists.is_none() {
        return Err(ApiError::NotFound);
    }
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM software_inventories WHERE host_id=$1 AND inventory_key<>$2",
    )
    .bind(host_id)
    .bind(key)
    .fetch_one(&mut *tx)
    .await?;
    if count >= 100 {
        return Err(ApiError::BadRequest(
            "Höchstens 100 zusätzliche Inventare pro Host.".into(),
        ));
    }
    let (id,generation): (i64,i64)=sqlx::query_as(
        "INSERT INTO software_inventories(host_id,inventory_key,label,kind,identity,format,spec_version) VALUES($1,$2,$3,$4,$5,$6,$7) \
         ON CONFLICT(host_id,inventory_key) DO UPDATE SET label=EXCLUDED.label,kind=EXCLUDED.kind,identity=EXCLUDED.identity, \
         format=EXCLUDED.format,spec_version=EXCLUDED.spec_version,generation=software_inventories.generation+1,imported_at=now(), \
         scanned_at=NULL,scan_source_id=NULL,scan_error=NULL RETURNING id,generation"
    ).bind(host_id).bind(key).bind(&input.label).bind(&input.kind).bind(&input.identity).bind(parsed.format).bind(&parsed.spec_version)
        .fetch_one(&mut *tx).await?;
    sqlx::query("DELETE FROM software_components WHERE inventory_id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    let components = &parsed.components;
    sqlx::query("INSERT INTO software_components(inventory_id,component_ref,name,version,purl,ecosystem,location) \
        SELECT $1,r,n,v,p,e,l FROM UNNEST($2::text[],$3::text[],$4::text[],$5::text[],$6::text[],$7::text[]) t(r,n,v,p,e,l)")
        .bind(id).bind(components.iter().map(|c|c.reference.clone()).collect::<Vec<_>>())
        .bind(components.iter().map(|c|c.name.clone()).collect::<Vec<_>>())
        .bind(components.iter().map(|c|c.version.clone()).collect::<Vec<_>>())
        .bind(components.iter().map(|c|c.purl.clone()).collect::<Vec<_>>())
        .bind(components.iter().map(|c|c.ecosystem.clone()).collect::<Vec<_>>())
        .bind(components.iter().map(|c|c.location.clone()).collect::<Vec<_>>())
        .execute(&mut *tx).await?;
    crate::live::notify(&mut tx, "software_inventory", Some(host_id), None).await;
    tx.commit().await?;
    Ok(Json(
        json!({"id":id,"generation":generation,"components":components.len(),"format":parsed.format}),
    ))
}

pub async fn remove(
    _: CsrfAuthed<authz::p::HostsWrite>,
    State(st): State<AppState>,
    Path((host_id, key)): Path<(i64, String)>,
) -> ApiResult<StatusCode> {
    let mut tx = st.pool.begin().await?;
    let removed =
        sqlx::query("DELETE FROM software_inventories WHERE host_id=$1 AND inventory_key=$2")
            .bind(host_id)
            .bind(key)
            .execute(&mut *tx)
            .await?;
    if removed.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    crate::live::notify(&mut tx, "software_inventory", Some(host_id), None).await;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn scan(
    user: CsrfAuthed<authz::p::SourcesRun>,
    State(st): State<AppState>,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    if !user.0.can(authz::Permission::HostsRead) || !user.0.can(authz::Permission::CvesRead) {
        return Err(ApiError::Forbidden(
            "Für die Prüfung werden hosts.read und cves.read benötigt.",
        ));
    }
    crate::software_scan::scan(&st, id).await
}
