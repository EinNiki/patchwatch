//! Kennzahlen der letzten Läufe je Quelle: letzter Lauf und Median der letzten zehn (nur Zahlen, nie Antwortinhalte).

use serde::Serialize;
use serde_json::Value;
use sqlx::PgPool;
use std::collections::BTreeMap;

/// So viele abgeschlossene Läufe fließen in den Median ein.
pub const WINDOW: i64 = 10;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct LastRun {
    pub status: String,
    pub total_ms: i64,
    /// Dauer je Phase in Millisekunden.
    pub phases: Value,
    pub requests: Option<i32>,
    pub retries: Option<i32>,
    pub wait_ms: Option<i64>,
    pub page_size: Option<i32>,
    pub bytes: i64,
    /// Über das Netz übertragen; `None` = nicht messbar (der HTTP-Client entpackt gzip selbst).
    pub bytes_wire: Option<i64>,
    pub bytes_unpacked: Option<i64>,
    /// Geschriebene Datenbankzeilen (unveränderte zählen nicht).
    pub rows_written: Option<i64>,
    pub statuses: Value,
}

/// Summe der letzten 24 Stunden (nur Zahlen).
#[derive(Debug, Clone, Default, Serialize, PartialEq, sqlx::FromRow)]
pub struct Day {
    pub runs: i64,
    pub not_modified: i64,
    /// Summe der gemessenen Übertragung; Läufe ohne Messung fehlen hier (`unmeasured`).
    pub bytes_wire: i64,
    pub bytes_unpacked: i64,
    pub rows_written: i64,
    /// Läufe mit Daten, deren Übertragungsmenge nicht messbar war.
    pub unmeasured: i64,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
pub struct RunStats {
    pub last: Option<LastRun>,
    pub day: Day,
    /// Median der Gesamtdauer der letzten (bis zu) zehn erfolgreich abgeschlossenen Läufe in Millisekunden.
    pub median_ms: Option<i64>,
    /// Median je Phase über dieselben Läufe.
    pub phase_median_ms: BTreeMap<String, i64>,
    /// Anzahl der Läufe, die in die Mediane eingingen.
    pub runs: usize,
}

/// Median (bei gerader Anzahl der Mittelwert der beiden mittleren, abgerundet); `None` ohne Werte.
pub fn median(values: &mut [i64]) -> Option<i64> {
    if values.is_empty() {
        return None;
    }
    values.sort_unstable();
    let n = values.len();
    Some(if n % 2 == 1 {
        values[n / 2]
    } else {
        (values[n / 2 - 1] + values[n / 2]) / 2
    })
}

#[derive(sqlx::FromRow)]
struct Row {
    source: String,
    status: String,
    total_ms: i64,
    phases: Value,
    requests: Option<i32>,
    retries: Option<i32>,
    wait_ms: Option<i64>,
    page_size: Option<i32>,
    bytes: i64,
    bytes_wire: Option<i64>,
    bytes_unpacked: Option<i64>,
    rows_written: Option<i64>,
    statuses: Value,
}

/// Aus Zeilen (je Quelle neueste zuerst) die Kennzahlen bilden.
fn build(rows: Vec<Row>) -> BTreeMap<String, RunStats> {
    let mut by: BTreeMap<String, Vec<Row>> = BTreeMap::new();
    for r in rows {
        by.entry(r.source.clone()).or_default().push(r);
    }
    by.into_iter()
        .map(|(source, rows)| {
            let last = rows.first().map(|r| LastRun {
                status: r.status.clone(),
                total_ms: r.total_ms,
                phases: r.phases.clone(),
                requests: r.requests,
                retries: r.retries,
                wait_ms: r.wait_ms,
                page_size: r.page_size,
                bytes: r.bytes,
                bytes_wire: r.bytes_wire,
                bytes_unpacked: r.bytes_unpacked,
                rows_written: r.rows_written,
                statuses: r.statuses.clone(),
            });
            // Mediane nur über Läufe, die ihre Arbeit abschlossen (nicht Fehlschläge oder Abbrüche).
            let done: Vec<&Row> = rows
                .iter()
                .filter(|r| matches!(r.status.as_str(), "ok" | "not_modified" | "incomplete"))
                .take(WINDOW as usize)
                .collect();
            let mut totals: Vec<i64> = done.iter().map(|r| r.total_ms).collect();
            let mut per: BTreeMap<String, Vec<i64>> = BTreeMap::new();
            for r in &done {
                if let Some(o) = r.phases.as_object() {
                    for (k, v) in o {
                        if let Some(ms) = v.as_i64() {
                            per.entry(k.clone()).or_default().push(ms);
                        }
                    }
                }
            }
            let stats = RunStats {
                last,
                day: Day::default(),
                median_ms: median(&mut totals),
                phase_median_ms: per
                    .into_iter()
                    .filter_map(|(k, mut v)| median(&mut v).map(|m| (k, m)))
                    .collect(),
                runs: done.len(),
            };
            (source, stats)
        })
        .collect()
}

/// Kennzahlen je Quelle aus den zuletzt beendeten Läufen (je Quelle höchstens die letzten zehn plus der jüngste).
pub async fn load(pool: &PgPool) -> sqlx::Result<BTreeMap<String, RunStats>> {
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT source, status, total_ms, phases, requests, retries, wait_ms, page_size, bytes, bytes_wire, bytes_unpacked, rows_written, statuses FROM ( \
           SELECT source, status, \
                  (EXTRACT(EPOCH FROM (finished_at - started_at)) * 1000)::bigint AS total_ms, \
                  phases, requests, retries, wait_ms, page_size, bytes, bytes_wire, bytes_unpacked, rows_written, statuses, \
                  row_number() OVER (PARTITION BY source ORDER BY id DESC) AS n \
           FROM feed_runs \
           WHERE finished_at IS NOT NULL AND started_at IS NOT NULL AND status IN ('ok', 'not_modified', 'incomplete', 'failed') \
         ) t WHERE n <= 25 ORDER BY source, n",
    )
    .fetch_all(pool)
    .await?;
    let mut out = build(rows);
    // Summe der letzten 24 Stunden je Quelle (nur beendete Läufe).
    let days: Vec<(String, i64, i64, i64, i64, i64, i64)> = sqlx::query_as(
        "SELECT source, count(*), count(*) FILTER (WHERE status = 'not_modified'), \
                COALESCE(sum(bytes_wire), 0)::bigint, COALESCE(sum(bytes_unpacked), 0)::bigint, COALESCE(sum(rows_written), 0)::bigint, \
                count(*) FILTER (WHERE bytes_wire IS NULL AND COALESCE(bytes_unpacked, 0) > 0) \
         FROM feed_runs WHERE finished_at > now() - interval '24 hours' AND status IN ('ok', 'not_modified', 'incomplete', 'failed') GROUP BY source",
    )
    .fetch_all(pool)
    .await?;
    for (source, runs, not_modified, bytes_wire, bytes_unpacked, rows_written, unmeasured) in days {
        out.entry(source).or_default().day = Day {
            runs,
            not_modified,
            bytes_wire,
            bytes_unpacked,
            rows_written,
            unmeasured,
        };
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn row(status: &str, total: i64, dl: i64) -> Row {
        Row {
            source: "ubuntu".into(),
            status: status.into(),
            total_ms: total,
            phases: json!({"download": dl, "parse": 10}),
            requests: Some(3),
            retries: Some(0),
            wait_ms: Some(0),
            page_size: Some(10),
            bytes: 100,
            bytes_wire: None,
            bytes_unpacked: Some(100),
            rows_written: Some(0),
            statuses: json!({"200": 3}),
        }
    }

    #[test]
    fn median_of_odd_even_and_empty() {
        assert_eq!(median(&mut []), None);
        assert_eq!(median(&mut [5, 1, 9]), Some(5));
        assert_eq!(median(&mut [4, 1, 9, 2]), Some(3));
    }

    #[test]
    fn stats_use_the_last_ten_completed_runs_and_show_the_newest_run() {
        // Neuester Lauf ist ein Fehlschlag: er steht als "letzter Lauf", fließt aber nicht in den Median ein.
        let mut rows = vec![row("failed", 999_999, 999_999)];
        for i in 0..12 {
            rows.push(row("ok", 1000 + i * 100, 500 + i * 10));
        }
        let s = build(rows).remove("ubuntu").unwrap();
        assert_eq!(s.last.as_ref().unwrap().status, "failed");
        assert_eq!(s.runs, 10);
        // Zehn neueste erfolgreiche: 1000..1900 -> Median (1400 + 1500) / 2
        assert_eq!(s.median_ms, Some(1450));
        assert_eq!(s.phase_median_ms["parse"], 10);
        assert_eq!(s.phase_median_ms["download"], 545);
    }
}
