//! Zeitpläne, die zur Laufzeit in der UI änderbar sind (Tabelle `settings`): Feed-Intervalle je Quelle,
//! Report-Anforderung auf Serverseite, "meldet sich nicht"-Schwelle. Validierung und Fälligkeit liegen hier,
//! damit sie ohne Datenbank testbar sind.

use chrono::{DateTime, Duration, LocalResult, NaiveTime, TimeZone, Utc};
use chrono_tz::Tz;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::ops::RangeInclusive;

pub const FEED_INTERVAL_RANGE: RangeInclusive<i64> = 15..=1440;
pub const REPORT_EVERY_HOURS_RANGE: RangeInclusive<i64> = 1..=168;
pub const STALE_HOURS_RANGE: RangeInclusive<i64> = 1..=720;

pub const STALE_KEY: &str = "stale_after_hours";
pub const REPORTS_KEY: &str = "schedule.reports";
pub const REPORTS_LAST_RUN_KEY: &str = "schedule.reports.last_run";

pub fn feed_key(source: &str) -> String {
    format!("schedule.feeds.interval_minutes.{source}")
}

/// Zeitplan für die serverseitige Report-Anforderung. Der Server sagt dem Agent weiterhin nur "jetzt melden".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReportSchedule {
    Off,
    Interval { every_hours: i64 },
    Daily { at: String, tz: String },
}

impl ReportSchedule {
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Off => Ok(()),
            Self::Interval { every_hours } if REPORT_EVERY_HOURS_RANGE.contains(every_hours) => {
                Ok(())
            }
            Self::Interval { .. } => Err(format!(
                "Report-Intervall: {} bis {} Stunden",
                REPORT_EVERY_HOURS_RANGE.start(),
                REPORT_EVERY_HOURS_RANGE.end()
            )),
            Self::Daily { at, tz } => {
                parse_hhmm(at)?;
                parse_tz(tz)?;
                Ok(())
            }
        }
    }

    /// Nächster Zeitpunkt (> `now`, bei überfälligem Lauf `now`), zu dem Reports angefordert werden; `None` bei `Off`
    /// (und beim Intervall, solange noch kein Lauf gezählt wurde).
    pub fn next_due(
        &self,
        last_run: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
    ) -> Option<DateTime<Utc>> {
        match self {
            Self::Off => None,
            Self::Interval { every_hours } => {
                Some((last_run? + Duration::hours(*every_hours)).max(now))
            }
            Self::Daily { at, tz } => {
                if self.last_due(last_run, now).is_some() {
                    return Some(now); // Lauf ist überfällig, der Scheduler löst ihn innerhalb einer Minute aus
                }
                let (t, tz) = (parse_hhmm(at).ok()?, parse_tz(tz).ok()?);
                let today = now.with_timezone(&tz).date_naive();
                [today, today.succ_opt()?, today.succ_opt()?.succ_opt()?]
                    .into_iter()
                    .find_map(|d| {
                        let local = match tz.from_local_datetime(&d.and_time(t)) {
                            LocalResult::Single(x) => x,
                            LocalResult::Ambiguous(first, _) => first,
                            LocalResult::None => return None,
                        };
                        let utc = local.with_timezone(&Utc);
                        (utc > now).then_some(utc)
                    })
            }
        }
    }

    /// Letzter Zeitpunkt (<= `now`), zu dem eine Anforderung fällig war; `None` bei `Off`.
    /// Fällig ist der Plan, wenn der letzte Lauf davor liegt.
    pub fn last_due(
        &self,
        last_run: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
    ) -> Option<DateTime<Utc>> {
        match self {
            Self::Off => None,
            Self::Interval { every_hours } => {
                // Ohne bisherigen Lauf zählt der Start der Zählung nicht als fällig (setzt `last_run` beim Speichern).
                let last = last_run?;
                let due = last + Duration::hours(*every_hours);
                (due <= now).then_some(due)
            }
            Self::Daily { at, tz } => {
                let (t, tz) = (parse_hhmm(at).ok()?, parse_tz(tz).ok()?);
                let today = now.with_timezone(&tz).date_naive();
                let latest = [today, today.pred_opt()?].into_iter().find_map(|d| {
                    let local = match tz.from_local_datetime(&d.and_time(t)) {
                        LocalResult::Single(x) => x,
                        LocalResult::Ambiguous(first, _) => first,
                        // Lücke der Sommerzeit-Umstellung: die Uhrzeit existiert nicht, der Tag entfällt.
                        LocalResult::None => return None,
                    };
                    let utc = local.with_timezone(&Utc);
                    (utc <= now).then_some(utc)
                })?;
                // Schon ausgeführt, wenn der letzte Lauf nicht vor dem fälligen Zeitpunkt liegt.
                match last_run {
                    Some(l) if l >= latest => None,
                    _ => Some(latest),
                }
            }
        }
    }
}

pub fn parse_hhmm(s: &str) -> Result<NaiveTime, String> {
    let bytes = s.as_bytes();
    let shape_ok = bytes.len() == 5
        && bytes[2] == b':'
        && bytes
            .iter()
            .enumerate()
            .all(|(i, b)| i == 2 || b.is_ascii_digit());
    if !shape_ok {
        return Err("Uhrzeit im Format HH:MM angeben".into());
    }
    NaiveTime::parse_from_str(s, "%H:%M")
        .map_err(|_| "Uhrzeit im Format HH:MM angeben (00:00 bis 23:59)".into())
}

pub fn parse_tz(s: &str) -> Result<Tz, String> {
    s.parse::<Tz>()
        .map_err(|_| "Unbekannte Zeitzone (IANA-Name, z. B. Europe/Berlin)".into())
}

pub fn validate_feed_interval(minutes: i64) -> Result<(), String> {
    if FEED_INTERVAL_RANGE.contains(&minutes) {
        Ok(())
    } else {
        Err(format!(
            "Feed-Intervall: {} bis {} Minuten",
            FEED_INTERVAL_RANGE.start(),
            FEED_INTERVAL_RANGE.end()
        ))
    }
}

pub fn validate_stale_hours(hours: i64) -> Result<(), String> {
    if STALE_HOURS_RANGE.contains(&hours) {
        Ok(())
    } else {
        Err(format!(
            "\"Meldet sich nicht\": {} bis {} Stunden",
            STALE_HOURS_RANGE.start(),
            STALE_HOURS_RANGE.end()
        ))
    }
}

async fn get(pool: &PgPool, key: &str) -> Option<Value> {
    sqlx::query_scalar::<_, Value>("SELECT value FROM settings WHERE key = $1")
        .bind(key)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
}

pub async fn set(pool: impl sqlx::PgExecutor<'_>, key: &str, value: &Value) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO settings (key, value) VALUES ($1, $2) \
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()",
    )
    .bind(key)
    .bind(value)
    .execute(pool)
    .await?;
    Ok(())
}

/// Feed-Intervall einer Quelle in Minuten: UI-Wert vor Konfiguration; ungültige Werte fallen zurück.
pub async fn feed_interval_minutes(pool: &PgPool, source: &str, fallback: i64) -> i64 {
    get(pool, &feed_key(source))
        .await
        .and_then(|v| v.as_i64())
        .filter(|m| FEED_INTERVAL_RANGE.contains(m))
        .unwrap_or(fallback)
}

/// Einstellungsschlüssel des Intervalls der Massendaten (täglicher Import) einer Quelle.
pub fn bulk_key(source: &str) -> String {
    format!("schedule.feeds.bulk_interval_minutes.{source}")
}

/// Intervall des täglichen Massendaten-Imports in Minuten (Standard aus der Konfiguration).
pub async fn bulk_interval_minutes(pool: &PgPool, source: &str, fallback: i64) -> i64 {
    get(pool, &bulk_key(source))
        .await
        .and_then(|v| v.as_i64())
        .filter(|m| FEED_INTERVAL_RANGE.contains(m))
        .unwrap_or(fallback)
}

/// Stunden ohne Report, ab denen ein Host als "meldet sich nicht" gilt.
pub async fn stale_after_hours(pool: &PgPool, fallback: i64) -> i64 {
    get(pool, STALE_KEY)
        .await
        .and_then(|v| v.as_i64())
        .filter(|h| STALE_HOURS_RANGE.contains(h))
        .unwrap_or(fallback)
}

pub async fn stale_after(pool: &PgPool, fallback: i64) -> Duration {
    Duration::hours(stale_after_hours(pool, fallback).await)
}

pub async fn report_schedule(pool: &PgPool) -> ReportSchedule {
    get(pool, REPORTS_KEY)
        .await
        .and_then(|v| serde_json::from_value::<ReportSchedule>(v).ok())
        .filter(|s| s.validate().is_ok())
        .unwrap_or(ReportSchedule::Off)
}

pub async fn reports_last_run(pool: &PgPool) -> Option<DateTime<Utc>> {
    get(pool, REPORTS_LAST_RUN_KEY)
        .await
        .and_then(|v| v.as_str().and_then(|s| s.parse().ok()))
}

/// Beansprucht den fälligen Lauf atomar: nur eine Instanz gewinnt, ein zweiter Aufruf für denselben Zeitpunkt nicht.
pub async fn claim_report_run(
    pool: &PgPool,
    due: DateTime<Utc>,
    now: DateTime<Utc>,
) -> sqlx::Result<bool> {
    let claimed = sqlx::query(
        "INSERT INTO settings (key, value) VALUES ($1, to_jsonb($2::text)) \
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now() \
         WHERE (settings.value #>> '{}')::timestamptz < $3",
    )
    .bind(REPORTS_LAST_RUN_KEY)
    .bind(now.to_rfc3339())
    .bind(due)
    .execute(pool)
    .await?
    .rows_affected()
        > 0;
    Ok(claimed)
}

/// Fertige Beschreibung für die API (nie Geheimnisse, nur Zahlen und Zeitpunkte).
pub fn report_schedule_json(
    s: &ReportSchedule,
    last_run: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
) -> Value {
    let mut v = serde_json::to_value(s).unwrap_or_else(|_| json!({ "mode": "off" }));
    v["last_run"] = json!(last_run);
    v["due_now"] = json!(s.last_due(last_run, now).is_some());
    v["next_run"] = json!(s.next_due(last_run, now));
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> DateTime<Utc> {
        s.parse().unwrap()
    }

    #[test]
    fn next_due_for_interval_and_daily() {
        let now = at("2026-11-01T10:00:00Z");
        let iv = ReportSchedule::Interval { every_hours: 6 };
        assert_eq!(
            iv.next_due(Some(at("2026-11-01T08:00:00Z")), now),
            Some(at("2026-11-01T14:00:00Z"))
        );
        // Überfällig: sofort.
        assert_eq!(
            iv.next_due(Some(at("2026-11-01T01:00:00Z")), now),
            Some(now)
        );
        assert_eq!(iv.next_due(None, now), None);
        assert_eq!(ReportSchedule::Off.next_due(None, now), None);
        let daily = ReportSchedule::Daily {
            at: "04:00".into(),
            tz: "UTC".into(),
        };
        assert_eq!(
            daily.next_due(Some(at("2026-11-01T04:00:00Z")), now),
            Some(at("2026-11-02T04:00:00Z"))
        );
        let later = ReportSchedule::Daily {
            at: "23:30".into(),
            tz: "UTC".into(),
        };
        assert_eq!(
            later.next_due(Some(at("2026-10-31T23:30:00Z")), now),
            Some(at("2026-11-01T23:30:00Z"))
        );
    }

    #[test]
    fn feed_interval_bounds() {
        assert!(validate_feed_interval(14).is_err());
        assert!(validate_feed_interval(15).is_ok());
        assert!(validate_feed_interval(1440).is_ok());
        assert!(validate_feed_interval(1441).is_err());
        assert!(validate_feed_interval(-1).is_err());
    }

    #[test]
    fn stale_hours_bounds() {
        assert!(validate_stale_hours(0).is_err());
        assert!(validate_stale_hours(1).is_ok());
        assert!(validate_stale_hours(720).is_ok());
        assert!(validate_stale_hours(721).is_err());
    }

    #[test]
    fn hhmm_and_tz_validation() {
        assert!(parse_hhmm("03:30").is_ok());
        for bad in [
            "3:30", "24:00", "12:60", "12-30", "12:3x", "", "123:45", "+1:00",
        ] {
            assert!(parse_hhmm(bad).is_err(), "{bad}");
        }
        assert!(parse_tz("Europe/Berlin").is_ok());
        assert!(parse_tz("Mars/Olympus").is_err());
        assert!(parse_tz("").is_err());
    }

    #[test]
    fn report_schedule_validation() {
        assert!(ReportSchedule::Off.validate().is_ok());
        assert!(ReportSchedule::Interval { every_hours: 0 }
            .validate()
            .is_err());
        assert!(ReportSchedule::Interval { every_hours: 169 }
            .validate()
            .is_err());
        assert!(ReportSchedule::Interval { every_hours: 6 }
            .validate()
            .is_ok());
        let d = |a: &str, z: &str| ReportSchedule::Daily {
            at: a.into(),
            tz: z.into(),
        };
        assert!(d("04:00", "Europe/Berlin").validate().is_ok());
        assert!(d("4:00", "Europe/Berlin").validate().is_err());
        assert!(d("04:00", "Nowhere").validate().is_err());
    }

    #[test]
    fn json_shape_is_fixed() {
        let s: ReportSchedule =
            serde_json::from_str(r#"{"mode":"daily","at":"04:00","tz":"UTC"}"#).unwrap();
        assert_eq!(
            s,
            ReportSchedule::Daily {
                at: "04:00".into(),
                tz: "UTC".into()
            }
        );
        assert!(serde_json::from_str::<ReportSchedule>(
            r#"{"mode":"daily","at":"04:00","tz":"UTC","x":1}"#
        )
        .is_err());
        assert!(serde_json::from_str::<ReportSchedule>(r#"{"mode":"cron"}"#).is_err());
    }

    #[test]
    fn interval_due_after_period() {
        let s = ReportSchedule::Interval { every_hours: 6 };
        let last = at("2026-10-31T00:00:00Z");
        assert_eq!(s.last_due(Some(last), at("2026-10-31T05:59:00Z")), None);
        assert_eq!(
            s.last_due(Some(last), at("2026-10-31T06:00:00Z")),
            Some(at("2026-10-31T06:00:00Z"))
        );
        // Ohne bisherigen Lauf wird nicht sofort ausgelöst.
        assert_eq!(s.last_due(None, at("2026-10-31T06:00:00Z")), None);
        assert_eq!(
            ReportSchedule::Off.last_due(Some(last), at("2027-01-01T00:00:00Z")),
            None
        );
    }

    #[test]
    fn daily_uses_timezone() {
        let s = ReportSchedule::Daily {
            at: "04:00".into(),
            tz: "Europe/Berlin".into(),
        };
        // 31.10.2026: Berlin = UTC+1 (Sommerzeit endet am 25.10.) -> 04:00 lokal = 03:00 UTC.
        assert_eq!(
            s.last_due(None, at("2026-10-31T02:59:00Z")),
            Some(at("2026-10-30T03:00:00Z"))
        );
        assert_eq!(
            s.last_due(None, at("2026-10-31T03:00:00Z")),
            Some(at("2026-10-31T03:00:00Z"))
        );
        // Im Sommer (UTC+2) ist es 02:00 UTC.
        assert_eq!(
            s.last_due(None, at("2026-07-01T02:00:00Z")),
            Some(at("2026-07-01T02:00:00Z"))
        );
    }

    #[test]
    fn daily_runs_once_per_day() {
        let s = ReportSchedule::Daily {
            at: "04:00".into(),
            tz: "UTC".into(),
        };
        let now = at("2026-10-31T09:00:00Z");
        assert_eq!(s.last_due(Some(at("2026-10-31T04:00:05Z")), now), None);
        assert_eq!(
            s.last_due(Some(at("2026-10-30T04:00:05Z")), now),
            Some(at("2026-10-31T04:00:00Z"))
        );
    }

    #[test]
    fn daily_skips_nonexistent_dst_time() {
        // 29.03.2026: in Berlin springt die Uhr von 02:00 auf 03:00; 02:30 existiert nicht.
        let s = ReportSchedule::Daily {
            at: "02:30".into(),
            tz: "Europe/Berlin".into(),
        };
        // Am Umstelltag fällt der Lauf aus; letzter fälliger Lauf bleibt der des Vortags.
        assert_eq!(
            s.last_due(None, at("2026-03-29T12:00:00Z")),
            Some(at("2026-03-28T01:30:00Z"))
        );
    }
}
