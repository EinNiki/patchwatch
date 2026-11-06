//! Feed-Daten speichern, Änderungen erkennen und Events erzeugen.

use super::{Entry, Record, SourceStatus};
use anyhow::Result;
use serde_json::{json, Value};
use sqlx::PgConnection;
use std::collections::{HashMap, HashSet};

const BATCH: usize = 5000;
const MAX_EVENTS: usize = 200;
const MAX_CHANGES_PER_EVENT: usize = 12;

#[derive(Debug, Default)]
pub struct IngestStats {
    pub new_cves: usize,
    pub changed_rows: usize,
    /// (Release, Paket)-Paare mit neuen oder geänderten Einträgen; bestimmen, welche Hosts neu bewertet werden.
    pub changed_pairs: HashSet<(String, String)>,
    pub events: usize,
}

struct Change {
    release: String,
    package: String,
    from: Option<String>,
    to: SourceStatus,
    fix_version: Option<String>,
}

/// Vorsichtigste Reihenfolge, falls eine Quelle denselben Eintrag mehrfach liefert (bei OSV üblich).
fn caution(s: SourceStatus) -> u8 {
    match s {
        SourceStatus::Vulnerable => 4,
        SourceStatus::Unknown => 3,
        SourceStatus::FixPending => 2,
        SourceStatus::Fixed => 1,
        SourceStatus::NotAffected => 0,
    }
}

/// Doppelte Einträge je (Release, Paket) zu einem zusammenfassen; ein Batch-Upsert darf einen Schlüssel
/// nur einmal enthalten. Bei Widerspruch gewinnt der vorsichtigere Status.
fn dedupe_entries(entries: Vec<Entry>) -> Vec<Entry> {
    let mut map: HashMap<(String, String), Entry> = HashMap::new();
    for e in entries {
        match map.entry((e.release.clone(), e.package.clone())) {
            std::collections::hash_map::Entry::Vacant(v) => {
                v.insert(e);
            }
            std::collections::hash_map::Entry::Occupied(mut o) => {
                if caution(e.status) > caution(o.get().status) {
                    o.insert(e);
                }
            }
        }
    }
    let mut out: Vec<Entry> = map.into_values().collect();
    out.sort_by(|a, b| (&a.release, &a.package).cmp(&(&b.release, &b.package)));
    out
}

/// Records derselben CVE (z. B. Debian: `linux` und `linux-6.12`) zusammenführen.
fn merge(records: &[Record]) -> Vec<Record> {
    let mut map: HashMap<&str, Record> = HashMap::new();
    for r in records {
        let m = map.entry(r.cve_id.as_str()).or_insert_with(|| Record {
            cve_id: r.cve_id.clone(),
            ..Record::default()
        });
        m.description = m.description.take().or_else(|| r.description.clone());
        m.priority = m.priority.take().or_else(|| r.priority.clone());
        m.published_at = m.published_at.or(r.published_at);
        m.updated_at = m.updated_at.max(r.updated_at);
        m.entries.extend(r.entries.iter().cloned());
    }
    map.into_values()
        .map(|mut r| {
            r.entries = dedupe_entries(std::mem::take(&mut r.entries));
            r
        })
        .collect()
}

/// Schreibt Records einer Quelle. Läuft in der Transaktion des Aufrufers, damit Daten und Feed-Zustand
/// gemeinsam übernommen oder verworfen werden. Der allererste Import einer Quelle erzeugt keine Events.
pub async fn ingest(
    conn: &mut PgConnection,
    source: &str,
    records: &[Record],
) -> Result<IngestStats> {
    ingest_with(conn, source, source, records, true).await
}

/// Wie [`ingest`]; `emit_events = false` für Anreicherungsquellen (NVD, CISA KEV): deren Einträge ändern keinen
/// Fix-Stand und sollen keine "CVE-Status geändert"-Meldungen auslösen.
pub async fn ingest_with(
    conn: &mut PgConnection,
    source: &str,
    source_id: &str,
    records: &[Record],
    emit_events: bool,
) -> Result<IngestStats> {
    let recs = merge(records);
    let ids: Vec<String> = recs.iter().map(|r| r.cve_id.clone()).collect();
    let initial: bool =
        sqlx::query_scalar("SELECT NOT EXISTS (SELECT 1 FROM cve_source_status WHERE source = $1)")
            .bind(source)
            .fetch_one(&mut *conn)
            .await?;
    let known: HashSet<String> = sqlx::query_scalar("SELECT id FROM cves WHERE id = ANY($1)")
        .bind(&ids)
        .fetch_all(&mut *conn)
        .await?
        .into_iter()
        .collect();

    #[allow(clippy::type_complexity)]
    let existing: HashMap<(String, String, String), (String, Option<String>, Option<Value>)> =
        sqlx::query_as::<_, (String, String, String, String, Option<String>, Option<Value>)>(
            "SELECT cve_id, release, package, status, fix_version, raw->'suites' FROM cve_source_status WHERE source = $1 AND cve_id = ANY($2)",
        )
        .bind(source)
        .bind(&ids)
        .fetch_all(&mut *conn)
        .await?
        .into_iter()
        .map(|(c, r, p, s, f, su)| ((c, r, p), (s, f, su)))
        .collect();

    // Rows left behind by a deleted source of the same type (same status, so they would be skipped as
    // "unchanged" below) are adopted by the current source; otherwise they would stay excluded from evaluation.
    sqlx::query(
        "UPDATE cve_source_status SET source_id = $2 WHERE source = $1 AND cve_id = ANY($3) AND source_id IS DISTINCT FROM $2",
    )
    .bind(source)
    .bind(source_id)
    .bind(&ids)
    .execute(&mut *conn)
    .await?;

    let mut stats = IngestStats::default();
    let mut upserts: Vec<(&Record, &Entry)> = Vec::new();
    let mut quiet: Vec<(&Record, &Entry)> = Vec::new();
    let mut by_cve: HashMap<&str, Vec<Change>> = HashMap::new();
    for r in &recs {
        for e in &r.entries {
            let key = (r.cve_id.clone(), e.release.clone(), e.package.clone());
            let old = existing.get(&key);
            let same = old.is_some_and(|(s, f, _)| s == e.status.as_str() && *f == e.fix_version);
            if same {
                // Suiten (Debian: Archiv/Security) nachziehen, ohne dass es als Änderung zählt (keine Ereignisse).
                if e.raw.get("suites").is_some()
                    && old.and_then(|(_, _, su)| su.as_ref()) != e.raw.get("suites")
                {
                    quiet.push((r, e));
                }
                continue;
            }
            stats.changed_rows += 1;
            stats
                .changed_pairs
                .insert((e.release.clone(), e.package.clone()));
            upserts.push((r, e));
            by_cve.entry(r.cve_id.as_str()).or_default().push(Change {
                release: e.release.clone(),
                package: e.package.clone(),
                from: old.map(|(s, _, _)| s.clone()),
                to: e.status,
                fix_version: e.fix_version.clone(),
            });
        }
    }
    stats.new_cves = by_cve.keys().filter(|c| !known.contains(**c)).count();

    // CVE-Stammdaten nur für neue oder geänderte CVEs schreiben (FK von cve_source_status).
    let touched: Vec<&Record> = recs
        .iter()
        .filter(|r| by_cve.contains_key(r.cve_id.as_str()) || !known.contains(&r.cve_id))
        .collect();
    for chunk in touched.chunks(BATCH) {
        sqlx::query(
            "INSERT INTO cves (id, description, priority, published_at, updated_at) \
             SELECT i, d, p, pub, COALESCE(u, now()) FROM UNNEST($1::text[], $2::text[], $3::text[], $4::timestamptz[], $5::timestamptz[]) AS t(i, d, p, pub, u) \
             ON CONFLICT (id) DO UPDATE SET description = COALESCE(EXCLUDED.description, cves.description), \
               priority = COALESCE(EXCLUDED.priority, cves.priority), \
               published_at = COALESCE(EXCLUDED.published_at, cves.published_at), updated_at = EXCLUDED.updated_at",
        )
        .bind(chunk.iter().map(|r| r.cve_id.clone()).collect::<Vec<_>>())
        .bind(chunk.iter().map(|r| r.description.clone()).collect::<Vec<_>>())
        .bind(chunk.iter().map(|r| r.priority.clone()).collect::<Vec<_>>())
        .bind(chunk.iter().map(|r| r.published_at).collect::<Vec<_>>())
        .bind(chunk.iter().map(|r| r.updated_at).collect::<Vec<_>>())
        .execute(&mut *conn)
        .await?;
    }
    for chunk in quiet.chunks(BATCH) {
        sqlx::query(
            "UPDATE cve_source_status t SET raw = v.w::jsonb \
             FROM UNNEST($2::text[], $3::text[], $4::text[], $5::text[]) AS v(c, r, p, w) \
             WHERE t.source = $1 AND t.cve_id = v.c AND t.release = v.r AND t.package = v.p",
        )
        .bind(source)
        .bind(
            chunk
                .iter()
                .map(|(r, _)| r.cve_id.clone())
                .collect::<Vec<_>>(),
        )
        .bind(
            chunk
                .iter()
                .map(|(_, e)| e.release.clone())
                .collect::<Vec<_>>(),
        )
        .bind(
            chunk
                .iter()
                .map(|(_, e)| e.package.clone())
                .collect::<Vec<_>>(),
        )
        .bind(
            chunk
                .iter()
                .map(|(_, e)| e.raw.to_string())
                .collect::<Vec<_>>(),
        )
        .execute(&mut *conn)
        .await?;
    }
    for chunk in upserts.chunks(BATCH) {
        sqlx::query(
            "INSERT INTO cve_source_status (cve_id, source, release, package, status, fix_version, raw, source_id) \
             SELECT c, $1, r, p, s, f, w::jsonb, $8 FROM UNNEST($2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[]) AS t(c, r, p, s, f, w) \
             ON CONFLICT (cve_id, source, release, package) DO UPDATE SET status = EXCLUDED.status, \
               fix_version = EXCLUDED.fix_version, raw = EXCLUDED.raw, source_id = EXCLUDED.source_id, updated_at = now()",
        )
        .bind(source)
        .bind(chunk.iter().map(|(r, _)| r.cve_id.clone()).collect::<Vec<_>>())
        .bind(chunk.iter().map(|(_, e)| e.release.clone()).collect::<Vec<_>>())
        .bind(chunk.iter().map(|(_, e)| e.package.clone()).collect::<Vec<_>>())
        .bind(chunk.iter().map(|(_, e)| e.status.as_str().to_owned()).collect::<Vec<_>>())
        .bind(chunk.iter().map(|(_, e)| e.fix_version.clone()).collect::<Vec<_>>())
        .bind(chunk.iter().map(|(_, e)| e.raw.to_string()).collect::<Vec<_>>())
        .bind(source_id)
        .execute(&mut *conn)
        .await?;
    }

    if !initial && emit_events {
        for (cve, changes) in by_cve.iter().take(MAX_EVENTS) {
            let kind = if known.contains(*cve) {
                "cve_status_changed"
            } else {
                "cve_new"
            };
            let list: Vec<Value> = changes
                .iter()
                .take(MAX_CHANGES_PER_EVENT)
                .map(|c| json!({ "release": c.release, "package": c.package, "from": c.from, "to": c.to.as_str(), "fix_version": c.fix_version }))
                .collect();
            sqlx::query("INSERT INTO events (kind, payload) VALUES ($1, $2)")
                .bind(kind)
                .bind(json!({ "cve_id": cve, "source": source, "changes": list, "total_changes": changes.len() }))
                .execute(&mut *conn)
                .await?;
            stats.events += 1;
        }
        if by_cve.len() > MAX_EVENTS {
            tracing::warn!(
                source,
                cves = by_cve.len(),
                "mehr Änderungen als Events, Rest ohne Event gespeichert"
            );
        }
        sqlx::query("SELECT pg_notify('pw_events', '')")
            .execute(&mut *conn)
            .await?;
    }
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(rel: &str, pkg: &str, st: SourceStatus, fix: Option<&str>) -> Entry {
        Entry {
            release: rel.into(),
            package: pkg.into(),
            status: st,
            fix_version: fix.map(str::to_owned),
            raw: json!({}),
        }
    }

    /// Regression: doppelte Schlüssel im selben Batch ließen den ganzen Import scheitern
    /// ("ON CONFLICT DO UPDATE command cannot affect row a second time").
    #[test]
    fn duplicate_entries_are_collapsed_conservatively() {
        let out = dedupe_entries(vec![
            e("noble", "linux", SourceStatus::Fixed, Some("6.8.0-35.35")),
            e("noble", "linux", SourceStatus::Vulnerable, None),
            e("noble", "linux", SourceStatus::NotAffected, None),
            e("jammy", "linux", SourceStatus::Fixed, Some("5.15.0-1.1")),
        ]);
        assert_eq!(out.len(), 2);
        assert_eq!(out[1].status, SourceStatus::Vulnerable);
        assert_eq!(out[0].release, "jammy");
    }

    #[test]
    fn merge_combines_records_of_one_cve_and_dedupes() {
        let r = |pkg: &str, st| Record {
            cve_id: "CVE-2024-0001".into(),
            entries: vec![e("trixie", pkg, st, None)],
            ..Record::default()
        };
        let m = merge(&[
            r("linux", SourceStatus::Fixed),
            r("linux-6.12", SourceStatus::Vulnerable),
            r("linux", SourceStatus::Fixed),
        ]);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].entries.len(), 2);
    }
}
