use crate::error::{ApiError, ApiResult};
use crate::extract::{Admin, CsrfAdmin};
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

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
#[derive(Serialize, Clone)]
pub struct Distro {
    source: String,
    release: String,
    status: String,
    package: String,
    fix_version: Option<String>,
    updated_at: DateTime<Utc>,
    /// Release läuft auf mindestens einem Host.
    mine: bool,
    /// Anzahl Pakete dieser Quelle/Release.
    packages: usize,
}

/// Rang für „ungünstigster Status zuerst“.
fn severity(status: &str) -> u8 {
    match status {
        "vulnerable" => 0,
        "fix_pending" => 1,
        "unknown" => 2,
        "fixed" => 3,
        _ => 4,
    }
}

/// Fasst Quellenzeilen je (Quelle, Release) zusammen; Sortierung: Quelle, Release.
///
/// `used`: (Quelle, Release, Paket), auf die sich die Bewertung der Hosts stützt. Für Releases, die auf einem Host laufen,
/// zählen nur diese Pakete; sonst färbt z. B. `linux-nvidia` den Chip rot, obwohl der Host `linux` nutzt.
fn collapse(
    rows: Vec<SourceRow>,
    mine: &HashSet<String>,
    used: &HashSet<(String, String, String)>,
) -> Vec<Distro> {
    let mut by: BTreeMap<(String, String), Distro> = BTreeMap::new();
    let has_used =
        |source: &str, release: &str| used.iter().any(|(s, r, _)| s == source && r == release);
    for r in rows {
        if mine.contains(&r.release)
            && has_used(&r.source, &r.release)
            && !used.contains(&(r.source.clone(), r.release.clone(), r.package.clone()))
        {
            continue;
        }
        // Anreicherungsquellen (NVD, CISA KEV) führen Release "*": kein Distributions-Chip.
        if r.release == "*" {
            continue;
        }
        let key = (r.source.clone(), r.release.clone());
        match by.get_mut(&key) {
            Some(d) => {
                d.packages += 1;
                if severity(&r.status) < severity(&d.status) {
                    d.status = r.status;
                    d.package = r.package;
                    d.fix_version = r.fix_version;
                }
                d.updated_at = d.updated_at.max(r.updated_at);
            }
            None => {
                let m = mine.contains(&r.release);
                by.insert(
                    key,
                    Distro {
                        source: r.source,
                        release: r.release,
                        status: r.status,
                        package: r.package,
                        fix_version: r.fix_version,
                        updated_at: r.updated_at,
                        mine: m,
                        packages: 1,
                    },
                );
            }
        }
    }
    by.into_values().collect()
}

/// Quellenzeilen, auf die sich die Host-Bewertungen der CVEs stützen (siehe `collapse`).
async fn used_packages(
    st: &AppState,
    ids: &[String],
) -> ApiResult<HashMap<String, HashSet<(String, String, String)>>> {
    let rows: Vec<(String, String, String, String)> = sqlx::query_as(
        "SELECT DISTINCT h.cve_id, s->>'source', s->>'release', s->>'package' \
         FROM host_cve_status h CROSS JOIN LATERAL jsonb_array_elements(h.sources) s WHERE h.cve_id = ANY($1)",
    )
    .bind(ids)
    .fetch_all(&st.pool)
    .await?;
    let mut out: HashMap<String, HashSet<(String, String, String)>> = HashMap::new();
    for (cve, source, release, package) in rows {
        out.entry(cve)
            .or_default()
            .insert((source, release, package));
    }
    Ok(out)
}

/// Releases (Codenamen), die auf mindestens einem Host laufen.
async fn my_releases(st: &AppState) -> ApiResult<HashSet<String>> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT os_codename FROM hosts WHERE os_codename IS NOT NULL AND os_codename <> ''",
    )
    .fetch_all(&st.pool)
    .await?;
    Ok(rows.into_iter().collect())
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
    let in_scope = if all_releases {
        "true"
    } else {
        "s.release IN (SELECT os_codename FROM hosts WHERE os_codename IS NOT NULL)"
    };
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
    let exists = |source: &str, statuses: &str| {
        format!("EXISTS (SELECT 1 FROM cve_source_status s WHERE s.cve_id = c.id AND s.source = '{source}'{statuses} AND {in_scope})")
    };
    // Wer gezielt sucht, findet jede CVE; die Einschränkung gilt nur für die ungefilterte Liste.
    if !all_releases && pattern.is_none() {
        // Standardansicht: nur CVEs, die zu deinen Hosts gehören (Eintrag für ein laufendes Release, das nicht
        // „nicht betroffen“ ist, oder eine Bewertung eines Hosts) sowie beobachtete CVEs.
        conds.push(format!(
            "(w.cve_id IS NOT NULL OR EXISTS (SELECT 1 FROM host_cve_status x WHERE x.cve_id = c.id) \
             OR EXISTS (SELECT 1 FROM cve_source_status s WHERE s.cve_id = c.id AND s.status <> 'not_affected' AND {in_scope}))"
        ));
    }
    if let Some(d) = distro {
        conds.push(exists(d, ""));
    }
    for (source, state) in [("debian", debian_fix), ("ubuntu", ubuntu_fix)] {
        match state {
            Some("fixed") => conds.push(exists(source, " AND s.status = 'fixed'")),
            Some("open") => conds.push(exists(
                source,
                " AND s.status IN ('vulnerable','fix_pending')",
            )),
            _ => {}
        }
    }
    let filter = if conds.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conds.join(" AND "))
    };
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
    let sources: Vec<(String, SourceRow)> = sqlx::query_as::<_, SourceWithCve>(
        "SELECT cve_id, source, release, package, status, fix_version, updated_at FROM cve_source_status \
         WHERE cve_id = ANY($1) ORDER BY cve_id, source, release, package",
    )
    .bind(&ids)
    .fetch_all(&st.pool)
    .await?
    .into_iter()
    .map(SourceWithCve::split)
    .collect();
    let mine = my_releases(&st).await?;
    let used = used_packages(&st, &ids).await?;
    let no_used = HashSet::new();
    let mut per_cve: HashMap<String, Vec<SourceRow>> = HashMap::new();
    for (cve, row) in sources {
        per_cve.entry(cve).or_default().push(row);
    }
    let out = rows
        .into_iter()
        .map(|cve| {
            let all = collapse(
                per_cve.remove(&cve.id).unwrap_or_default(),
                &mine,
                used.get(&cve.id).unwrap_or(&no_used),
            );
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

#[derive(sqlx::FromRow)]
struct SourceWithCve {
    cve_id: String,
    source: String,
    release: String,
    package: String,
    status: String,
    fix_version: Option<String>,
    updated_at: DateTime<Utc>,
}

impl SourceWithCve {
    fn split(self) -> (String, SourceRow) {
        (
            self.cve_id,
            SourceRow {
                source: self.source,
                release: self.release,
                package: self.package,
                status: self.status,
                fix_version: self.fix_version,
                updated_at: self.updated_at,
            },
        )
    }
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
    let mine = my_releases(&st).await?;
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
    let used = used_packages(&st, std::slice::from_ref(&id)).await?;
    let distros = collapse(
        sources
            .iter()
            .map(|s| SourceRow {
                source: s.source.clone(),
                release: s.release.clone(),
                package: s.package.clone(),
                status: s.status.clone(),
                fix_version: s.fix_version.clone(),
                updated_at: s.updated_at,
            })
            .collect(),
        &mine,
        used.get(&id).unwrap_or(&HashSet::new()),
    );
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
