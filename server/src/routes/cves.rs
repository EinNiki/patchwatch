use crate::error::{ApiError, ApiResult};
use crate::extract::{Admin, CsrfAdmin};
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeSet, HashMap};

/// CVE-ID wie `CVE-2024-1086`.
pub fn valid_cve_id(id: &str) -> bool {
    let Some(rest) = id.strip_prefix("CVE-") else {
        return false;
    };
    let Some((year, num)) = rest.split_once('-') else {
        return false;
    };
    year.len() == 4
        && year.chars().all(|c| c.is_ascii_digit())
        && (4..=7).contains(&num.len())
        && num.chars().all(|c| c.is_ascii_digit())
}

#[derive(Deserialize)]
pub struct ListQuery {
    watchlist: Option<bool>,
    q: Option<String>,
    /// `mine` (Standard): nur Releases, die auf mindestens einem Host laufen; `all`: alle.
    releases: Option<String>,
    /// Nur CVEs mit Eintrag dieser Quelle (`debian`, `ubuntu`, `osv`).
    distro: Option<String>,
    /// Alt-URL: `debian_fixed_ubuntu_open` oder `ubuntu_fixed_debian_open` (Alias für `debian`/`ubuntu`).
    split: Option<String>,
    /// Fix-Stand je Distribution: `fixed` oder `open` (verwundbar oder Fix angekündigt); UND zwischen den Distributionen.
    debian: Option<String>,
    ubuntu: Option<String>,
    /// Sortierung: `latest` (Standard, neueste Veröffentlichung), `level` (Priorität 10→0) oder `updated`.
    sort: Option<String>,
    /// Richtung: `desc` (Standard) oder `asc`.
    dir: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct CveRow {
    id: String,
    description: Option<String>,
    priority: Option<String>,
    /// Priorität als Stufe 0–10 (0 = unbekannt), abgeleitet aus `priority`.
    #[sqlx(skip)]
    level: u8,
    published_at: Option<DateTime<Utc>>,
    updated_at: DateTime<Utc>,
    watched: bool,
    note: Option<String>,
    /// In der CISA-KEV-Liste (aktiv ausgenutzt).
    exploited: bool,
    hosts_vulnerable: i64,
    hosts_fix_pending: i64,
    hosts_unknown: i64,
}

#[derive(Serialize)]
pub struct CveOut {
    #[serde(flatten)]
    cve: CveRow,
    distros: Vec<Distro>,
    /// Anzahl Releases, die wegen `releases=mine` nicht in `distros` stehen.
    hidden_releases: usize,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct SourceRow {
    source: String,
    release: String,
    package: String,
    status: String,
    fix_version: Option<String>,
    updated_at: DateTime<Utc>,
}

/// Ein Chip je (Quelle, Release): der ungünstigste Status über alle Pakete.
#[derive(Serialize, Clone, sqlx::FromRow)]
pub struct Distro {
    #[serde(skip)]
    cve_id: String,
    source: String,
    release: String,
    status: String,
    package: String,
    fix_version: Option<String>,
    updated_at: DateTime<Utc>,
    /// Release läuft auf mindestens einem Host.
    mine: bool,
    /// Anzahl Pakete dieser Quelle/Release.
    packages: i64,
}

/// Rang für „ungünstigster Status zuerst“ (SQL; Chip-Status = kleinster Rang aller Pakete).
const SEVERITY_SQL: &str = "CASE s.status WHEN 'vulnerable' THEN 0 WHEN 'fix_pending' THEN 1 WHEN 'unknown' THEN 2 WHEN 'fixed' THEN 3 ELSE 4 END";
/// Release läuft auf mindestens einem Host (Umfang „meine Releases“).
const MINE_SQL: &str =
    "s.release IN (SELECT os_codename FROM hosts WHERE os_codename IS NOT NULL AND os_codename <> '')";

/// Die EINE Definition der Chips (Quelle, Release) einer CVE: Anzeige (Liste, Detail) und Filter lesen beide dieses
/// SQL, damit ein Chip, der „gefixt“ zeigt, vom Filter „gefixt“ gefunden wird (und umgekehrt).
///
/// Ein Chip fasst alle Pakete der Quelle/Release zusammen: der ungünstigste Status gewinnt (Rang `SEVERITY_SQL`, bei
/// Gleichstand das erste Paket alphabetisch). Für Releases, die auf einem Host laufen, zählen nur die Pakete, auf die
/// sich die Bewertung der Hosts stützt (`host_cve_status.sources`); sonst färbt z. B. `linux-nvidia` den Chip rot,
/// obwohl der Host `linux` nutzt. Anreicherungsquellen (NVD, CISA KEV) führen Release `*` und haben keinen Chip.
/// `ids` beschränkt auf die CVEs des Parameters `$1` (Anzeige), `source` auf eine Quelle (Filter); beides nur
/// Einschränkungen der Menge, nie der Definition. Mengenbasiert statt je CVE korreliert: ~0,2 s statt ~2 s bei 20 000 CVEs.
fn chips_sql(ids: bool, source: Option<&str>) -> String {
    let mut s_cond = vec!["s.release <> '*'".to_owned()];
    if ids {
        s_cond.push("s.cve_id = ANY($1)".into());
    }
    if let Some(src) = source {
        s_cond.push(format!("s.source = '{src}'"));
    }
    let hs_cond = if ids { "WHERE hs.cve_id = ANY($1)" } else { "" };
    let s_cond = s_cond.join(" AND ");
    format!(
        "SELECT DISTINCT ON (s.cve_id, s.source, s.release) s.cve_id, s.source, s.release, s.package, s.status, \
         s.fix_version, max(s.updated_at) OVER w AS updated_at, ({MINE_SQL}) AS mine, (count(*) OVER w)::int8 AS packages \
         FROM cve_source_status s \
         LEFT JOIN (SELECT hs.cve_id, u->>'source' AS source, u->>'release' AS release, array_agg(DISTINCT u->>'package') AS pkgs \
                    FROM host_cve_status hs CROSS JOIN LATERAL jsonb_array_elements(hs.sources) u {hs_cond} GROUP BY 1, 2, 3) ud \
                ON ud.cve_id = s.cve_id AND ud.source = s.source AND ud.release = s.release \
         WHERE {s_cond} AND NOT ({MINE_SQL} AND ud.pkgs IS NOT NULL AND NOT (s.package = ANY(ud.pkgs))) \
         WINDOW w AS (PARTITION BY s.cve_id, s.source, s.release) \
         ORDER BY s.cve_id, s.source, s.release, {SEVERITY_SQL}, s.package"
    )
}

/// Chips der angegebenen CVEs (siehe `chips_sql`), je CVE nach Quelle und Release sortiert.
async fn chips_for(st: &AppState, ids: &[String]) -> ApiResult<HashMap<String, Vec<Distro>>> {
    let rows: Vec<Distro> = sqlx::query_as(&chips_sql(true, None))
        .bind(ids)
        .fetch_all(&st.pool)
        .await?;
    let mut out: HashMap<String, Vec<Distro>> = HashMap::new();
    for d in rows {
        out.entry(d.cve_id.clone()).or_default().push(d);
    }
    Ok(out)
}

/// Quellen-Links je Quelle (feste Vorlagen; die CVE-ID ist vorher validiert).
fn source_link(source: &str, id: &str) -> Option<String> {
    match source {
        "ubuntu" => Some(format!("https://ubuntu.com/security/{id}")),
        "debian" => Some(format!("https://security-tracker.debian.org/tracker/{id}")),
        "osv" => Some(format!("https://osv.dev/vulnerability/{id}")),
        _ => None,
    }
}

/// SQL-Gegenstück zu `priority_level` (für die Sortierung); `c` ist die Tabelle `cves`.
const LEVEL_SQL: &str =
    "CASE c.priority WHEN 'critical' THEN 10 WHEN 'high' THEN 8 WHEN 'medium' THEN 5 \
    WHEN 'low' THEN 3 WHEN 'negligible' THEN 1 WHEN 'unimportant' THEN 1 ELSE 0 END";

/// Prioritätstext der Feeds (NVD, Debian, Ubuntu) als Stufe 0–10.
pub fn priority_level(p: Option<&str>) -> u8 {
    match p {
        Some("critical") => 10,
        Some("high") => 8,
        Some("medium") => 5,
        Some("low") => 3,
        Some("negligible" | "unimportant") => 1,
        _ => 0,
    }
}

/// Länge der Beschreibung in der Liste (Zeichen); die volle Beschreibung liefert `GET /cves/{id}`.
const LIST_DESCRIPTION_CHARS: usize = 300;

const CVE_SELECT: &str = "SELECT c.id, c.description, c.priority, c.published_at, c.updated_at, \
    (w.cve_id IS NOT NULL) AS watched, w.note, \
    EXISTS (SELECT 1 FROM cve_source_status k WHERE k.cve_id = c.id AND k.source = 'cisa_kev') AS exploited, \
    count(h.*) FILTER (WHERE h.status = 'vulnerable') AS hosts_vulnerable, \
    count(h.*) FILTER (WHERE h.status = 'fix_pending') AS hosts_fix_pending, \
    count(h.*) FILTER (WHERE h.status = 'unknown') AS hosts_unknown \
    FROM cves c LEFT JOIN cve_watchlist w ON w.cve_id = c.id LEFT JOIN host_cve_status h ON h.cve_id = c.id";

/// Ergebnis der Filterprüfung: gültige Parameter und die WHERE-Klausel (mit festen, geprüften Texten).
struct Built<'a> {
    distro: Option<&'a str>,
    pattern: Option<String>,
    filter: String,
}

/// Prüft die Filterparameter und baut die WHERE-Klausel der Liste. Die Liste und die Zählung "wie viele passen bei
/// Umfang alle" benutzen genau diese Funktion; nur `all_releases` unterscheidet sich.
fn build_filter(q: &ListQuery, all_releases: bool) -> ApiResult<Built<'_>> {
    let distro = match q.distro.as_deref() {
        None | Some("") => None,
        Some(d @ ("debian" | "ubuntu" | "osv")) => Some(d),
        Some(_) => {
            return Err(ApiError::BadRequest(
                "distro: debian, ubuntu oder osv".into(),
            ))
        }
    };
    // Alt-URL `split` ist ein Alias für zwei Fix-Filter; explizite Parameter haben Vorrang.
    let (split_debian, split_ubuntu) = match q.split.as_deref() {
        None | Some("") => (None, None),
        Some("debian_fixed_ubuntu_open") => (Some("fixed"), Some("open")),
        Some("ubuntu_fixed_debian_open") => (Some("open"), Some("fixed")),
        Some(_) => return Err(ApiError::BadRequest("split: ungültiger Wert".into())),
    };
    let fix_state = |v: &Option<String>, alias: Option<&'static str>, name: &str| match v.as_deref()
    {
        None | Some("") => Ok(alias),
        Some("fixed") => Ok(Some("fixed")),
        Some("open") => Ok(Some("open")),
        Some(_) => Err(ApiError::BadRequest(format!("{name}: fixed oder open"))),
    };
    let debian_fix = fix_state(&q.debian, split_debian, "debian")?;
    let ubuntu_fix = fix_state(&q.ubuntu, split_ubuntu, "ubuntu")?;
    // Postgres kann kein NUL in Text speichern oder vergleichen (sonst 500); Steuerzeichen sind in einer Suche sinnlos.
    if q.q
        .as_deref()
        .is_some_and(|s| s.chars().any(char::is_control))
    {
        return Err(ApiError::BadRequest("q: ungültige Zeichen".into()));
    }
    // LIKE-Metazeichen im Suchtext entschärfen.
    let pattern = q.q.as_deref().map(|s| {
        format!(
            "%{}%",
            s.replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_")
        )
    });
    // Die Filter werden als Konstanten in die Abfrage geschrieben (nur geprüfte Werte aus den festen Listen oben, nie
    // Nutzertext): Mit Parametern wählt der Planer einen generischen Plan und braucht für "Debian offen" ~0,5 s statt ~0,1 s.
    // Nutzertext (Suche) bleibt ein gebundener Parameter.
    let mut conds: Vec<String> = Vec::new();
    if q.watchlist == Some(true) {
        conds.push("w.cve_id IS NOT NULL".into());
    }
    if pattern.is_some() {
        // Sieht die Eingabe wie (der Anfang) einer CVE-ID aus, genügt die ID; die Volltextsuche in den Beschreibungen
        // liest alle Texte (~0,4 s bei 20 000 CVEs).
        let id_like = q.q.as_deref().is_some_and(|t| {
            // Bytes statt `t[..4]`: ein Zeichen (z. B. "é") über der Byte-Grenze 4 ließ den String-Slice paniken.
            t.as_bytes()
                .get(..4)
                .is_some_and(|p| p.eq_ignore_ascii_case(b"cve-"))
                && t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
        conds.push(if id_like {
            "c.id ILIKE $1".into()
        } else {
            "(c.id ILIKE $1 OR c.description ILIKE $1)".into()
        });
    }
    // Filter und Anzeige benutzen dieselben Chips (`chips_sql`) und denselben Umfang: „meine Releases“ (Standard)
    // oder „alle“. `statuses` sind feste Texte, nie Nutzereingabe.
    let scope_cond = if all_releases { "" } else { " AND ch.mine" };
    let chip_exists = |source: &str, statuses: &str| {
        format!(
            "c.id IN (SELECT ch.cve_id FROM ({}) ch WHERE ch.source = '{source}'{statuses}{scope_cond})",
            chips_sql(false, Some(source))
        )
    };
    // Wer gezielt sucht, findet jede CVE; die Einschränkung gilt nur für die ungefilterte Liste.
    if !all_releases && pattern.is_none() {
        // Standardansicht: nur CVEs, die zu deinen Hosts gehören (Eintrag für ein laufendes Release, das nicht
        // „nicht betroffen“ ist, oder eine Bewertung eines Hosts) sowie beobachtete CVEs.
        conds.push(format!(
            "(w.cve_id IS NOT NULL OR EXISTS (SELECT 1 FROM host_cve_status x WHERE x.cve_id = c.id AND x.status <> 'not_affected') \
             OR EXISTS (SELECT 1 FROM cve_source_status s WHERE s.cve_id = c.id AND s.status <> 'not_affected' AND {MINE_SQL}))"
        ));
    }
    if let Some(d) = distro {
        conds.push(chip_exists(d, ""));
    }
    for (source, state) in [("debian", debian_fix), ("ubuntu", ubuntu_fix)] {
        match state {
            Some("fixed") => conds.push(chip_exists(source, " AND ch.status = 'fixed'")),
            Some("open") => conds.push(chip_exists(
                source,
                " AND ch.status IN ('vulnerable','fix_pending')",
            )),
            _ => {}
        }
    }
    let filter = if conds.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conds.join(" AND "))
    };
    Ok(Built {
        distro,
        pattern,
        filter,
    })
}

/// Trefferzahl der aktuellen Filter je Umfang: `mine` (Releases auf meinen Hosts) und `all` (alle Releases). Für den
/// Leer-Zustand ("3 CVEs passen, wenn Releases ohne Host mitzählen"); benutzt dieselbe Filterlogik wie die Liste.
pub async fn scope_count(
    _: Admin,
    State(st): State<AppState>,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<Value>> {
    let mut out = serde_json::Map::new();
    for (name, all) in [("mine", false), ("all", true)] {
        let b = build_filter(&q, all)?;
        let sql = format!(
            "SELECT count(*) FROM cves c LEFT JOIN cve_watchlist w ON w.cve_id = c.id {}",
            b.filter
        );
        let mut query = sqlx::query_scalar::<_, i64>(&sql);
        if let Some(p) = &b.pattern {
            query = query.bind(p);
        }
        out.insert(name.into(), query.fetch_one(&st.pool).await?.into());
    }
    Ok(Json(Value::Object(out)))
}

pub async fn list(
    _: Admin,
    State(st): State<AppState>,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<Vec<CveOut>>> {
    let limit = q.limit.unwrap_or(100).clamp(1, 500);
    let offset = q.offset.unwrap_or(0).max(0);
    let all_releases = match q.releases.as_deref() {
        None | Some("mine") => false,
        Some("all") => true,
        Some(_) => return Err(ApiError::BadRequest("releases: mine oder all".into())),
    };
    // Beobachtete CVEs stehen immer oben; danach gilt die gewählte Sortierung (feste Texte, nie Nutzereingabe).
    let dir = match q.dir.as_deref() {
        None | Some("") | Some("desc") => "DESC",
        Some("asc") => "ASC",
        Some(_) => return Err(ApiError::BadRequest("dir: asc oder desc".into())),
    };
    let nulls = if dir == "DESC" {
        "NULLS LAST"
    } else {
        "NULLS FIRST"
    };
    let order = match q.sort.as_deref() {
        None | Some("") | Some("latest") => {
            format!("c.published_at {dir} {nulls}, c.id {dir}")
        }
        Some("level") => format!("{LEVEL_SQL} {dir}, c.published_at DESC NULLS LAST, c.id DESC"),
        Some("updated") => format!("c.updated_at {dir}, c.id {dir}"),
        Some(_) => {
            return Err(ApiError::BadRequest(
                "sort: latest, level oder updated".into(),
            ))
        }
    };
    let outer_order = order.replace("c.", "p.");
    let Built {
        distro,
        pattern,
        filter,
    } = build_filter(&q, all_releases)?;
    // Erst die Seite (Filter, Sortierung, LIMIT) bestimmen, danach nur für diese Zeilen Zähler und KEV-Flag bilden.
    // Eine Aggregation über alle CVEs vor dem LIMIT kostete ~190 ms bei 20 000 CVEs (siehe docs/perf.md).
    // Die Beschreibung wird für die Liste gekürzt (erst für die Zeilen der Seite, sonst wird sie für alle CVEs entpackt);
    // die volle steht im Detail.
    // limit und offset sind geklemmte Zahlen (keine Nutzerstrings) und stehen deshalb direkt in der Abfrage.
    let query = format!(
        "SELECT p.id, left(d.description, {LIST_DESCRIPTION_CHARS}) AS description, p.priority, p.published_at, p.updated_at, p.watched, p.note, \
         EXISTS (SELECT 1 FROM cve_source_status k WHERE k.cve_id = p.id AND k.source = 'cisa_kev') AS exploited, \
         hc.hosts_vulnerable, hc.hosts_fix_pending, hc.hosts_unknown \
         FROM (SELECT c.id, c.priority, c.published_at, c.updated_at, (w.cve_id IS NOT NULL) AS watched, w.note \
               FROM cves c LEFT JOIN cve_watchlist w ON w.cve_id = c.id {filter} \
               ORDER BY (w.cve_id IS NOT NULL) DESC, {order} LIMIT {limit} OFFSET {offset}) p \
         JOIN cves d ON d.id = p.id \
         CROSS JOIN LATERAL (SELECT count(*) FILTER (WHERE h.status = 'vulnerable') AS hosts_vulnerable, \
                                    count(*) FILTER (WHERE h.status = 'fix_pending') AS hosts_fix_pending, \
                                    count(*) FILTER (WHERE h.status = 'unknown') AS hosts_unknown \
                             FROM host_cve_status h WHERE h.cve_id = p.id) hc \
         ORDER BY p.watched DESC, {outer_order}"
    );
    let mut rows_query = sqlx::query_as::<_, CveRow>(&query);
    if let Some(p) = &pattern {
        rows_query = rows_query.bind(p);
    }
    let mut rows = rows_query.fetch_all(&st.pool).await?;
    for r in &mut rows {
        r.level = priority_level(r.priority.as_deref());
    }

    let ids: Vec<String> = rows.iter().map(|r| r.id.clone()).collect();
    let mut per_cve = chips_for(&st, &ids).await?;
    let out = rows
        .into_iter()
        .map(|cve| {
            let all = per_cve.remove(&cve.id).unwrap_or_default();
            let total = all.len();
            let distros: Vec<Distro> = all
                .into_iter()
                .filter(|d| all_releases || d.mine)
                .filter(|d| distro.is_none_or(|x| d.source == x))
                .collect();
            let hidden_releases = if all_releases {
                0
            } else {
                total - distros.len()
            };
            CveOut {
                cve,
                distros,
                hidden_releases,
            }
        })
        .collect();
    Ok(Json(out))
}

#[derive(Serialize, sqlx::FromRow)]
struct AffectedHost {
    id: i64,
    name: String,
    os_codename: Option<String>,
    status: String,
    reason: String,
}

pub async fn detail(
    _: Admin,
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    if !valid_cve_id(&id) {
        return Err(ApiError::BadRequest("ungültige CVE-ID".into()));
    }
    let cve = sqlx::query_as::<_, CveRow>(&format!(
        "{CVE_SELECT} WHERE c.id = $1 GROUP BY c.id, w.cve_id, w.note"
    ))
    .bind(&id)
    .fetch_optional(&st.pool)
    .await?
    .ok_or(ApiError::NotFound)?;
    let mut cve = cve;
    cve.level = priority_level(cve.priority.as_deref());
    let sources = sqlx::query_as::<_, SourceRow>(
        "SELECT source, release, package, status, fix_version, updated_at FROM cve_source_status \
         WHERE cve_id = $1 ORDER BY source, release, package",
    )
    .bind(&id)
    .fetch_all(&st.pool)
    .await?;
    let hosts = sqlx::query_as::<_, AffectedHost>(
        "SELECT h.id, h.name, h.os_codename, s.status, s.reason FROM host_cve_status s \
         JOIN hosts h ON h.id = s.host_id WHERE s.cve_id = $1 ORDER BY h.name",
    )
    .bind(&id)
    .fetch_all(&st.pool)
    .await?;
    let last_change = sources
        .iter()
        .map(|s| s.updated_at)
        .max()
        .map_or(cve.updated_at, |m| m.max(cve.updated_at));
    let seen: BTreeSet<&str> = sources.iter().map(|s| s.source.as_str()).collect();
    let links: Vec<Value> = seen
        .into_iter()
        .filter_map(|s| source_link(s, &id).map(|u| serde_json::json!({ "source": s, "url": u })))
        .collect();
    let distros = chips_for(&st, std::slice::from_ref(&id))
        .await?
        .remove(&id)
        .unwrap_or_default();
    Ok(Json(serde_json::json!({
        "cve": cve, "sources": sources, "distros": distros, "links": links,
        "last_change_at": last_change, "hosts": hosts,
    })))
}

pub async fn watchlist(admin: Admin, State(st): State<AppState>) -> ApiResult<Json<Vec<CveOut>>> {
    list(
        admin,
        State(st),
        Query(ListQuery {
            watchlist: Some(true),
            q: None,
            releases: None,
            distro: None,
            split: None,
            debian: None,
            sort: None,
            dir: None,
            ubuntu: None,
            limit: Some(500),
            offset: None,
        }),
    )
    .await
}

#[derive(Deserialize, Default)]
pub struct WatchBody {
    note: Option<String>,
}

/// Fügt eine CVE zur Watchlist hinzu (auch, wenn die Feeds sie noch nicht kennen).
pub async fn watch(
    CsrfAdmin(_): CsrfAdmin,
    State(st): State<AppState>,
    Path(id): Path<String>,
    body: Option<Json<WatchBody>>,
) -> ApiResult<StatusCode> {
    if !valid_cve_id(&id) {
        return Err(ApiError::BadRequest("ungültige CVE-ID".into()));
    }
    let note = body.and_then(|b| b.0.note).filter(|n| !n.is_empty());
    if note.as_ref().is_some_and(|n| n.len() > 500) {
        return Err(ApiError::BadRequest(
            "Notiz zu lang (max. 500 Zeichen)".into(),
        ));
    }
    let mut tx = st.pool.begin().await?;
    sqlx::query("INSERT INTO cves (id) VALUES ($1) ON CONFLICT DO NOTHING")
        .bind(&id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO cve_watchlist (cve_id, note) VALUES ($1, $2) ON CONFLICT (cve_id) DO UPDATE SET note = EXCLUDED.note")
        .bind(&id)
        .bind(note)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    // Die Neubewertung aller Hosts dauert Sekunden; die Antwort wartet nicht darauf.
    // Ergebnisse kommen wie sonst über host_cve_status-Events live in die Oberfläche.
    tokio::spawn(async move {
        if let Err(e) = crate::cve::reeval::reevaluate_all(&st).await {
            tracing::error!(error = %e, "Neubewertung nach Watchlist-Änderung fehlgeschlagen");
        }
    });
    Ok(StatusCode::NO_CONTENT)
}

pub async fn unwatch(
    CsrfAdmin(_): CsrfAdmin,
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    sqlx::query("DELETE FROM cve_watchlist WHERE cve_id = $1")
        .bind(&id)
        .execute(&st.pool)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cve_id_validation() {
        assert!(valid_cve_id("CVE-2024-1086"));
        assert!(valid_cve_id("CVE-2021-44228"));
        assert!(!valid_cve_id("cve-2024-1086"));
        assert!(!valid_cve_id("CVE-24-1086"));
        assert!(!valid_cve_id("CVE-2024-12"));
        assert!(!valid_cve_id("CVE-2024-1086; DROP"));
    }
}
