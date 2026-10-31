//! CVE-Feeds: Adapter hinter dem Trait [`CveSource`], Normalisierung, Bewertung, Ingestion.

pub mod debian;
pub mod eval;
pub mod http;
pub mod ingest;
pub mod kev;
pub mod nvd;
pub mod osv;
pub mod reeval;
pub mod refresh;
pub mod sources;
pub mod ubuntu;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
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
    pub cursor: Option<String>,
}

pub enum FetchOutcome {
    /// Quelle erreichbar, nichts Neues (HTTP 304 oder unveränderter Cursor).
    NotModified,
    Records {
        records: Vec<Record>,
        state: FeedState,
    },
}

#[derive(Debug)]
pub enum FeedError {
    Network(String),
    Http(u16),
    TooLarge(u64),
    /// Antwort hat nicht das erwartete Format (Quelle hat das Format geändert?).
    Format(String),
    /// Nicht alle Änderungen konnten in einem Lauf geladen werden.
    Incomplete(String),
}

impl fmt::Display for FeedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Network(m) => write!(f, "Netzwerkfehler: {m}"),
            Self::Http(c) => write!(f, "HTTP {c}"),
            Self::TooLarge(n) => write!(f, "Antwort größer als das Limit von {n} Bytes"),
            Self::Format(m) => write!(f, "unerwartetes Format: {m}"),
            Self::Incomplete(m) => write!(f, "unvollständig: {m}"),
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
