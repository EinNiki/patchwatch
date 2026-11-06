//! CVE-Feeds: Adapter hinter dem Trait [`CveSource`], Normalisierung, Bewertung, Ingestion.

pub mod debian;
pub mod eval;
pub mod http;
pub mod ingest;
pub mod kev;
pub mod nvd;
pub mod osv;
pub mod oval;
pub mod reeval;
pub mod refresh;
pub mod sources;
pub mod ubuntu;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;

/// Normalisierter Status eines Quelleneintrags für (CVE, Release, Paket).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceStatus {
    /// Betroffen, kein Fix verfügbar.
    Vulnerable,
    /// Fix angekündigt, aber noch nicht veröffentlicht.
    FixPending,
    /// Behoben ab `fix_version`.
    Fixed,
    NotAffected,
    /// Unklar oder noch nicht bewertet; wird nie als "grün" gewertet.
    Unknown,
}

impl SourceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Vulnerable => "vulnerable",
            Self::FixPending => "fix_pending",
            Self::Fixed => "fixed",
            Self::NotAffected => "not_affected",
            Self::Unknown => "unknown",
        }
    }

    pub fn parse(s: &str) -> Self {
        match s {
            "vulnerable" => Self::Vulnerable,
            "fix_pending" => Self::FixPending,
            "fixed" => Self::Fixed,
            "not_affected" => Self::NotAffected,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Entry {
    /// Codename der Distribution (z. B. `noble`, `trixie`).
    pub release: String,
    /// Quellpaket im Tracker (z. B. `linux`, `linux-hwe-6.8`).
    pub package: String,
    pub status: SourceStatus,
    pub fix_version: Option<String>,
    /// Originalangabe der Quelle zu diesem Eintrag (klein gehalten).
    pub raw: Value,
}

#[derive(Debug, Clone, Default)]
pub struct Record {
    pub cve_id: String,
    pub description: Option<String>,
    pub priority: Option<String>,
    pub published_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    pub entries: Vec<Entry>,
}

/// Zustand je Feed für bedingte Abrufe und inkrementelles Laden.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FeedState {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    /// Zuletzt BESTÄTIGTER Stand: alles, was neuer ist, ist vollständig geladen. Rückt nie über eine offene
    /// Lücke hinweg vor (siehe [`Backfill`]).
    pub cursor: Option<String>,
    /// Offener Rückstandsabbau (nur Quellen mit Cursor-Paginierung).
    pub backfill: Option<Backfill>,
    /// Horizont, bis zu dem der Erstabruf die Quelle vollständig geladen hat (nur Quellen mit Erstabruf-Abbau).
    pub covered_since: Option<String>,
    /// Hybridmodus (Ubuntu): Zustand der Massendaten je Release und des stündlichen Abrufs.
    pub bulk: Option<Bulk>,
    /// Ein vorhandener Rückstandsabbau, solange der Hybridmodus aktiv ist (nie gelöscht, im Modus `api` zurück).
    pub parked: Option<Backfill>,
    /// Nur vom Adapter gesetzt: bis wann die Quelle nach diesem Lauf nutzbar ist (überschreibt die Standardregel).
    pub usable_until: Option<DateTime<Utc>>,
}

/// Zustand der Massendaten (täglich) und des inkrementellen Abrufs (stündlich) einer Hybrid-Quelle.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bulk {
    #[serde(default)]
    pub releases: std::collections::BTreeMap<String, BulkRelease>,
    #[serde(default)]
    pub incr: Incr,
    /// Je Release mit gültigen Massendaten das Ende der Frische (`verified_at` + Frist). Nur Releases in dieser
    /// Liste gelten für Hosts als nutzbar; fehlt ein Release, ist die CVE-Lage dort "unbekannt".
    #[serde(default)]
    pub ok: std::collections::BTreeMap<String, DateTime<Utc>>,
    /// Alle relevanten Releases haben einen gültigen, frischen Import und der letzte Import keines Releases ist
    /// fehlgeschlagen. Nur dann zeigt die Oberfläche "vollständig".
    #[serde(default)]
    pub complete: bool,
    /// Relevante Releases des letzten Laufs (Hosts plus Konfiguration).
    #[serde(default)]
    pub relevant: Vec<String>,
}

/// Stand der Massendatei eines Releases.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BulkRelease {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    /// Letzter erfolgreicher Abruf (200 mit gültigem Inhalt oder 304).
    pub verified_at: Option<DateTime<Utc>>,
    /// Letzter Abruf mit neuem Inhalt (200).
    pub imported_at: Option<DateTime<Utc>>,
    pub bytes: Option<u64>,
    pub records: Option<u32>,
    /// Letzter Versuch und sein Ergebnis: `imported`, `not_modified` oder `error`.
    pub checked_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub last_result: String,
    pub last_error: Option<String>,
    pub last_status: Option<u16>,
    pub retry_after_secs: Option<u64>,
    #[serde(default)]
    pub failures: u32,
    pub next_attempt_at: Option<DateTime<Utc>>,
}

/// Stand des stündlichen Abrufs der ersten Seiten von `cves.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Incr {
    pub last_run_at: Option<DateTime<Utc>>,
    pub last_ok_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub last_status: Option<u16>,
    pub retry_after_secs: Option<u64>,
    /// Aktuelle Seitengröße (0 = Standard der Konfiguration) und gelerntes Maximum (nach HTTP 422).
    #[serde(default)]
    pub page_size: u32,
    pub max_page: Option<u32>,
    #[serde(default)]
    pub failures: u32,
    /// Fortschritt über Läufe, falls der Abstand zum bestätigten Cursor (`FeedState::cursor`) mehrere Läufe braucht:
    /// neuester gesehener Zeitstempel und Offset der nächsten Seite.
    pub pending: Option<String>,
    #[serde(default)]
    pub next_offset: u32,
    #[serde(default)]
    pub pages_last: u32,
}

/// Fortschritt eines Rückstandsabbaus (Catch-up nach einem Cursor oder Erstabruf bis zum Horizont). Die Lücke
/// liegt zwischen `target` (alter bestätigter Cursor bzw. Horizont) und dem Kopf der Liste. Fortschritt und bestätigter Cursor sind bewusst getrennt: `FeedState::cursor` bleibt
/// `target`, bis die Lücke geschlossen ist; erst dann wird er auf `pending` gesetzt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Backfill {
    /// Bestätigter Cursor zu Beginn der Lücke; bis hierhin muss gelesen werden.
    pub target: String,
    /// Neuester bisher gesehener Zeitstempel; wird zum bestätigten Cursor, sobald die Lücke zu ist.
    pub pending: String,
    /// Offset der nächsten Seite (liegt eine Seite vor dem zuletzt gelesenen Ende, siehe Überlappung).
    pub next_offset: u32,
    /// Insgesamt geladene Seiten (inkl. Überlappung) und Läufe seit Beginn der Lücke.
    pub pages_done: u32,
    pub runs: u32,
    pub started_at: DateTime<Utc>,
    /// Erstabruf (noch nie ein bestätigter Cursor): `target` ist dann der Horizont, nicht ein alter Cursor.
    #[serde(default)]
    pub initial: bool,
    /// Geschätzte Gesamtzahl der Seiten bis zum Ziel (nur Erstabruf; Schätzung, die Liste ändert sich laufend).
    #[serde(default)]
    pub est_pages: Option<u32>,
}

pub enum FetchOutcome {
    /// Quelle erreichbar, nichts Neues (HTTP 304 oder unveränderter Cursor).
    NotModified,
    /// Vollständiger Abruf: `state` wird übernommen (auch ein vorgerückter Cursor).
    Records {
        records: Vec<Record>,
        state: FeedState,
    },
    /// Teilabruf: die Records sind gültig und werden gespeichert, aber die Lücke ist noch offen. `state.cursor`
    /// bleibt der alte bestätigte Stand, `state.backfill` hält den Fortschritt. Die Quelle gilt weiter als
    /// unvollständig. `interrupted` nennt den Fehler, falls der Lauf mittendrin abbrach (sonst Seitenlimit).
    Partial {
        records: Vec<Record>,
        state: FeedState,
        interrupted: Option<String>,
        /// Wunsch der Gegenseite (`Retry-After`) für den nächsten Versuch, falls der Abbruch eine Drosselung war.
        retry_after: Option<std::time::Duration>,
    },
    /// Fehlschlag mit Zustand (Hybridquelle): nichts war nutzbar, aber die Einzelheiten (Fehler je Release, Seitengröße,
    /// geparkter Rückstandsabbau) müssen erhalten bleiben. Zählt wie ein Fehler (Leiter, Alarm, nie nutzbar).
    Failed { state: FeedState, error: FeedError },
}

#[derive(Debug)]
pub enum FeedError {
    Network(String),
    Http(u16),
    /// Quelle ist überlastet oder drosselt (429, 5xx). `retry_after` ist der (bereits gedeckelte) Wunsch der
    /// Gegenseite aus dem Header `Retry-After`, falls vorhanden.
    Throttled {
        status: u16,
        retry_after: Option<std::time::Duration>,
    },
    TooLarge(u64),
    /// Watchdog: der Lauf meldete so viele Minuten keinen Fortschritt und wurde abgebrochen.
    Stalled(u64),
    /// Antwort hat nicht das erwartete Format (Quelle hat das Format geändert?).
    Format(String),
}

impl fmt::Display for FeedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Network(m) => write!(f, "Netzwerkfehler: {m}"),
            Self::Http(c) | Self::Throttled { status: c, .. } => write!(f, "HTTP {c}"),
            Self::Stalled(m) => write!(f, "Lauf ohne Fortschritt seit {m} Minuten abgebrochen"),
            Self::TooLarge(n) => write!(f, "Antwort größer als das Limit von {n} Bytes"),
            Self::Format(m) => write!(f, "unerwartetes Format: {m}"),
        }
    }
}

impl std::error::Error for FeedError {}

/// Ein Host, wie ihn Quellen mit versionsbezogener Abfrage (OSV) brauchen.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HostRef {
    pub distro_id: String,
    pub os_version: String,
    pub codename: String,
    /// Quellpaket im Tracker (siehe [`eval::tracker_package`]).
    pub package: String,
    pub version: String,
}

#[derive(Debug, Clone, Default)]
pub struct FetchCtx {
    /// Watchlist-CVEs, zu denen diese Quelle noch keine Daten hat.
    pub watch_missing: Vec<String>,
    pub hosts: Vec<HostRef>,
    /// Nur Anreicherungsquellen (NVD): bereits bekannte CVEs ohne Daten dieser Quelle, Watchlist zuerst.
    pub enrich: Vec<String>,
    /// Lebenszeichen für den Watchdog des Schedulers (Fortschritt melden mit `progress.beat()`).
    pub progress: Heartbeat,
    /// Hybridquelle (Ubuntu): Intervall der Massendaten in Minuten aus den Einstellungen (0 = Konfigurationswert).
    pub bulk_interval_minutes: i64,
}

/// Gemeinsame Schnittstelle aller Feeds; weitere Quellen (Red Hat, Alpine …) kommen als eigener Adapter dazu.
#[async_trait]
pub trait CveSource: Send + Sync {
    fn name(&self) -> &'static str;
    async fn fetch(
        &self,
        http: &reqwest::Client,
        state: &FeedState,
        ctx: &FetchCtx,
    ) -> Result<FetchOutcome, FeedError>;
}

/// Kernel-Quellpaket? `linux`, `linux-hwe-6.8`, `linux-aws` … aber nicht `linux-firmware` o. Ä.
pub fn is_kernel_source(name: &str) -> bool {
    const NOT_KERNEL: &[&str] = &[
        "linux-firmware",
        "linux-base",
        "linux-meta",
        "linux-signed",
        "linux-restricted-modules",
        "linux-atm",
        "linux-ftpd",
        "linux-ftpd-ssl",
        "linux-entra-sso",
        "linux-tools",
        "linux-libc-dev",
        "linux-wlan-ng",
    ];
    if name == "linux" {
        return true;
    }
    name.starts_with("linux-")
        && !NOT_KERNEL
            .iter()
            .any(|n| name == *n || name.strip_prefix(n).is_some_and(|r| r.starts_with('-')))
}

/// `CVE-YYYY-NNNN…`; Quellen wie Debian enthalten auch Nicht-CVE-IDs (`TEMP-…`), die wir überspringen.
pub fn is_cve_id(id: &str) -> bool {
    crate::routes::valid_cve_id(id)
}

/// Gültige Debian-Version als Fix-Angabe? Sonst darf daraus kein "behoben" werden.
pub fn valid_version(v: &str) -> bool {
    v.parse::<debversion::Version>().is_ok()
}

pub fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_owned()
    } else {
        s.chars().take(max).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_source_detection() {
        for yes in [
            "linux",
            "linux-hwe-6.8",
            "linux-aws",
            "linux-6.12",
            "linux-lowlatency-hwe-5.15",
            "linux-oem-osp1",
        ] {
            assert!(is_kernel_source(yes), "{yes}");
        }
        for no in [
            "linux-firmware",
            "linux-atm",
            "linux-ftpd-ssl",
            "linux-entra-sso",
            "linux-meta-aws",
            "linux-signed-hwe",
            "linuxptp",
            "openssl",
            "linux-libc-dev",
        ] {
            assert!(!is_kernel_source(no), "{no}");
        }
    }

    #[test]
    fn status_roundtrip() {
        for s in [
            SourceStatus::Vulnerable,
            SourceStatus::FixPending,
            SourceStatus::Fixed,
            SourceStatus::NotAffected,
            SourceStatus::Unknown,
        ] {
            assert_eq!(SourceStatus::parse(s.as_str()), s);
        }
        assert_eq!(SourceStatus::parse("quatsch"), SourceStatus::Unknown);
    }
}

/// Lebenszeichen eines laufenden Abrufs: Quellen melden damit Fortschritt (z. B. eine geladene Seite). Der
/// Scheduler gibt einen Lauf frei, wenn das letzte Lebenszeichen zu lange zurückliegt.
#[derive(Debug, Clone)]
pub struct Heartbeat(std::sync::Arc<std::sync::Mutex<std::time::Instant>>);

impl Default for Heartbeat {
    fn default() -> Self {
        Self(std::sync::Arc::new(std::sync::Mutex::new(
            std::time::Instant::now(),
        )))
    }
}

impl Heartbeat {
    pub fn beat(&self) {
        if let Ok(mut t) = self.0.lock() {
            *t = std::time::Instant::now();
        }
    }

    /// Zeit seit dem letzten Lebenszeichen.
    pub fn idle(&self) -> std::time::Duration {
        self.0
            .lock()
            .map_or(std::time::Duration::ZERO, |t| t.elapsed())
    }
}
