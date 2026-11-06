//! Massendaten für Ubuntu: Canonical-OVAL-Dateien je Release (`com.ubuntu.<release>.cve.oval.xml.bz2`).
//!
//! Die Dateien sind 5 bis 13 MB groß (entpackt rund 240 MB). Sie werden gestreamt geladen, gestreamt entpackt und
//! gestreamt geparst; nie liegt die ganze Datei im Speicher. Übernommen werden **nur behobene Kernel-Einträge**
//! ("kernel 'linux' in noble was vulnerable but has been fixed (note: '6.8.0-100.100')"). Offene Einträge der Datei
//! ("Kernel X läuft", ohne Fixkriterium) unterscheiden nicht zwischen needed, pending und ignored und sind für einige
//! Varianten falsch; fehlende Einträge sind mehrdeutig (nicht betroffen oder unbekannt). Beides wird nicht gespeichert:
//! fehlende Information bedeutet "unbekannt" (siehe docs/ubuntu-source.md).

use super::http::{parse_retry_after, RETRY_AFTER_CAP};
use super::{BulkRelease, Entry, FeedError, Heartbeat, Record, SourceStatus};
use chrono::{DateTime, NaiveDate, Utc};
use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;
use std::io::{self, BufReader, Read};
use std::time::Duration;

/// Grenzen und Ziel eines Imports.
#[derive(Debug, Clone)]
pub struct OvalParams {
    pub base_url: String,
    /// Obergrenze der komprimierten Datei und der entpackten XML-Daten (Bytes) sowie der Gesamtdauer.
    pub max_bytes: u64,
    pub max_xml_bytes: u64,
    pub timeout: Duration,
}

/// Ergebnis der bedingten Anfrage für ein Release.
#[derive(Debug)]
pub enum Imported {
    /// 304: die Datei hat sich nicht geändert, der gespeicherte Stand bleibt gültig.
    NotModified,
    Data {
        records: Vec<Record>,
        etag: Option<String>,
        last_modified: Option<String>,
        /// Größe der komprimierten Datei.
        bytes: u64,
    },
}

/// Nur Codenamen der Form `noble`, `jammy`, `resolute`: der Name landet in einer URL.
pub fn valid_release(release: &str) -> bool {
    !release.is_empty()
        && release.len() <= 32
        && release
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

pub fn file_url(base: &str, release: &str) -> String {
    format!(
        "{}/com.ubuntu.{release}.cve.oval.xml.bz2",
        base.trim_end_matches('/')
    )
}

/// Begrenzt die Menge der gelesenen (entpackten) Bytes; mehr ist ein Fehler, kein stilles Abschneiden.
struct Capped<R> {
    inner: R,
    left: u64,
}

impl<R: Read> Read for Capped<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.left == 0 {
            let mut probe = [0u8; 1];
            return match self.inner.read(&mut probe)? {
                0 => Ok(0),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "entpackte Datei größer als das Limit",
                )),
            };
        }
        let max = buf
            .len()
            .min(usize::try_from(self.left).unwrap_or(usize::MAX));
        let n = self.inner.read(&mut buf[..max])?;
        self.left -= n as u64;
        Ok(n)
    }
}

/// Liest die vom asynchronen Download gelieferten Blöcke als `Read` (für den blockierenden Parser).
struct ChannelRead {
    rx: tokio::sync::mpsc::Receiver<io::Result<Vec<u8>>>,
    cur: Vec<u8>,
    pos: usize,
}

impl Read for ChannelRead {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.pos < self.cur.len() {
                let n = buf.len().min(self.cur.len() - self.pos);
                buf[..n].copy_from_slice(&self.cur[self.pos..self.pos + n]);
                self.pos += n;
                return Ok(n);
            }
            match self.rx.blocking_recv() {
                Some(Ok(chunk)) => {
                    self.cur = chunk;
                    self.pos = 0;
                }
                Some(Err(e)) => return Err(e),
                None => return Ok(0),
            }
        }
    }
}

/// Fixversion und Paketname aus einem Kriterium wie
/// `'linux-aws' kernel in noble was vulnerable but has been fixed (note: '6.8.0-1046.49').`
fn fixed_kernel(comment: &str, release: &str) -> Option<(String, String)> {
    let rest = comment.strip_prefix('\'')?;
    let (pkg, rest) = rest.split_once("' kernel in ")?;
    let rest = rest.strip_prefix(release)?;
    let rest = rest.strip_prefix(" was vulnerable but has been fixed (note: '")?;
    let (ver, _) = rest.split_once("')")?;
    let safe_pkg = pkg.starts_with("linux")
        && pkg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-._+".contains(c));
    let safe_ver = !ver.is_empty()
        && ver.len() <= 100
        && ver
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-+~:_".contains(c));
    (safe_pkg && safe_ver).then(|| (pkg.to_owned(), ver.to_owned()))
}

fn attr(e: &BytesStart<'_>, name: &[u8]) -> Option<String> {
    e.attributes()
        .flatten()
        .find(|a| a.key.as_ref() == name)
        .and_then(|a| a.unescape_value().ok().map(|v| v.into_owned()))
}

/// Parst eine `cve.oval.xml` eines Releases gestreamt. Fehler (Abschnitt fehlt, kaputtes XML, abgeschnittene oder
/// zu große Datei) ergeben `Err`; es werden nie Teilergebnisse geliefert.
pub fn parse_cve_oval<R: Read>(
    input: R,
    release: &str,
    max_xml_bytes: u64,
) -> Result<Vec<Record>, FeedError> {
    let capped = Capped {
        inner: input,
        left: max_xml_bytes,
    };
    let mut reader = Reader::from_reader(BufReader::with_capacity(64 * 1024, capped));
    let mut buf = Vec::new();
    let mut records: Vec<Record> = Vec::new();
    let (mut saw_definitions, mut saw_end) = (false, false);
    let mut in_def = false;
    let mut in_desc = false;
    let (mut cve_id, mut priority, mut public, mut desc): (
        Option<String>,
        Option<String>,
        Option<String>,
        String,
    ) = (None, None, None, String::new());
    let mut comments: Vec<String> = Vec::new();
    loop {
        let ev = reader
            .read_event_into(&mut buf)
            .map_err(|e| FeedError::Format(format!("OVAL-Datei unlesbar: {e}")))?;
        match ev {
            Event::Eof => break,
            Event::Start(e) => match e.local_name().as_ref() {
                b"definitions" => saw_definitions = true,
                b"definition" => {
                    in_def = attr(&e, b"class").as_deref() == Some("vulnerability");
                    (cve_id, priority, public) = (None, None, None);
                    desc.clear();
                    comments.clear();
                }
                b"description" if in_def => in_desc = true,
                b"cve" if in_def => {
                    priority = attr(&e, b"priority");
                    public = attr(&e, b"public");
                }
                _ => {}
            },
            Event::Empty(e) if in_def => match e.local_name().as_ref() {
                b"reference"
                    if attr(&e, b"source").as_deref() == Some("CVE") && cve_id.is_none() =>
                {
                    cve_id = attr(&e, b"ref_id");
                }
                b"criterion" => {
                    if let Some(c) = attr(&e, b"comment") {
                        // Nur Kriterien, die einen Behoben-Eintrag beschreiben, werden gebraucht.
                        if c.contains("has been fixed") {
                            comments.push(c);
                        }
                    }
                }
                _ => {}
            },
            Event::Text(t) if in_desc && desc.len() < 4000 => {
                if let Ok(s) = t.decode() {
                    desc.push_str(&s);
                }
            }
            Event::GeneralRef(r) if in_desc => {
                if let Ok(name) = r.decode() {
                    desc.push_str(match name.as_ref() {
                        "amp" => "&",
                        "lt" => "<",
                        "gt" => ">",
                        "quot" => "\"",
                        "apos" => "'",
                        _ => "",
                    });
                }
            }
            Event::End(e) => match e.local_name().as_ref() {
                b"description" => in_desc = false,
                b"definitions" => saw_end = true,
                b"definition" if in_def => {
                    in_def = false;
                    let mut entries: Vec<Entry> = comments
                        .iter()
                        .filter_map(|c| fixed_kernel(c, release))
                        .map(|(package, version)| Entry {
                            release: release.to_owned(),
                            package,
                            status: SourceStatus::Fixed,
                            fix_version: Some(version),
                            raw: serde_json::json!({ "origin": "oval" }),
                        })
                        .collect();
                    entries.sort_by(|a, b| a.package.cmp(&b.package));
                    entries.dedup_by(|a, b| a.package == b.package);
                    let id = cve_id.take().filter(|i| super::is_cve_id(i));
                    if let (Some(cve_id), false) = (id, entries.is_empty()) {
                        records.push(Record {
                            cve_id,
                            description: Some(desc.trim().to_owned()).filter(|d| !d.is_empty()),
                            priority: priority.take().map(|p| p.to_lowercase()),
                            published_at: public.take().and_then(|p| parse_public(&p)),
                            updated_at: None,
                            entries,
                        });
                    }
                }
                _ => {}
            },
            _ => {}
        }
        buf.clear();
    }
    // Eine Datei ohne vollständigen <definitions>-Block ist kaputt oder abgeschnitten, nie "leer".
    if !saw_definitions || !saw_end {
        return Err(FeedError::Format(
            "OVAL-Datei unvollständig (kein </definitions>)".into(),
        ));
    }
    Ok(records)
}

fn parse_public(p: &str) -> Option<DateTime<Utc>> {
    NaiveDate::parse_from_str(p, "%Y%m%d")
        .ok()
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .map(|d| d.and_utc())
}

/// Eine OVAL-Datei bedingt laden (`If-None-Match`/`If-Modified-Since` aus dem gespeicherten Stand) und auswerten.
/// `client` darf Weiterleitungen nur auf denselben Host folgen (siehe `bulk_client`).
pub async fn import_release(
    client: &reqwest::Client,
    release: &str,
    prev: &BulkRelease,
    p: &OvalParams,
    beat: &Heartbeat,
) -> Result<Imported, FeedError> {
    if !valid_release(release) {
        return Err(FeedError::Format(format!(
            "ungültiger Release-Name {release:?}"
        )));
    }
    let url = file_url(&p.base_url, release);
    match tokio::time::timeout(
        p.timeout,
        import_inner(client, release, &url, prev, p, beat),
    )
    .await
    {
        Ok(r) => r,
        Err(_) => Err(FeedError::Network(format!(
            "Import überschritt das Zeitlimit von {} Sekunden",
            p.timeout.as_secs()
        ))),
    }
}

async fn import_inner(
    client: &reqwest::Client,
    release: &str,
    url: &str,
    prev: &BulkRelease,
    p: &OvalParams,
    beat: &Heartbeat,
) -> Result<Imported, FeedError> {
    let mut req = client.get(url);
    if let Some(e) = &prev.etag {
        req = req.header(reqwest::header::IF_NONE_MATCH, e);
    }
    if let Some(m) = &prev.last_modified {
        req = req.header(reqwest::header::IF_MODIFIED_SINCE, m);
    }
    let mut resp = req
        .send()
        .await
        .map_err(|e| FeedError::Network(e.without_url().to_string()))?;
    let status = resp.status();
    if status == reqwest::StatusCode::NOT_MODIFIED {
        return Ok(Imported::NotModified);
    }
    if !status.is_success() {
        let code = status.as_u16();
        if code == 429 || code >= 500 {
            let retry_after = resp
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| parse_retry_after(v, Utc::now(), RETRY_AFTER_CAP));
            return Err(FeedError::Throttled {
                status: code,
                retry_after,
            });
        }
        return Err(FeedError::Http(code));
    }
    if resp.content_length().is_some_and(|n| n > p.max_bytes) {
        return Err(FeedError::TooLarge(p.max_bytes));
    }
    let header = |n: reqwest::header::HeaderName| {
        resp.headers()
            .get(n)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    let (etag, last_modified) = (
        header(reqwest::header::ETAG),
        header(reqwest::header::LAST_MODIFIED),
    );

    let (tx, rx) = tokio::sync::mpsc::channel::<io::Result<Vec<u8>>>(8);
    let (rel, max_xml) = (release.to_owned(), p.max_xml_bytes);
    let parser = tokio::task::spawn_blocking(move || {
        let decoder = bzip2::read::BzDecoder::new(ChannelRead {
            rx,
            cur: Vec::new(),
            pos: 0,
        });
        parse_cve_oval(decoder, &rel, max_xml)
    });
    let mut bytes = 0u64;
    let mut net_err: Option<FeedError> = None;
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                bytes += chunk.len() as u64;
                if bytes > p.max_bytes {
                    net_err = Some(FeedError::TooLarge(p.max_bytes));
                    break;
                }
                beat.beat();
                if tx.send(Ok(chunk.to_vec())).await.is_err() {
                    break; // der Parser hat schon aufgehört (Fehler); sein Ergebnis folgt unten
                }
            }
            Ok(None) => break,
            Err(e) => {
                net_err = Some(FeedError::Network(e.without_url().to_string()));
                let _ = tx
                    .send(Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "abgebrochen",
                    )))
                    .await;
                break;
            }
        }
    }
    drop(tx);
    let parsed = parser
        .await
        .map_err(|e| FeedError::Format(format!("Auswertung abgebrochen: {e}")))?;
    if let Some(e) = net_err {
        return Err(e);
    }
    Ok(Imported::Data {
        records: parsed?,
        etag,
        last_modified,
        bytes,
    })
}

/// Client für die Massendaten: ehrlicher User-Agent, Weiterleitungen nur auf denselben Host (nie auf fremde Hosts).
pub fn bulk_client() -> reqwest::Client {
    let policy = reqwest::redirect::Policy::custom(|attempt| {
        let same_host = attempt
            .previous()
            .first()
            .is_some_and(|first| first.host_str() == attempt.url().host_str());
        if same_host && attempt.previous().len() < 3 {
            attempt.follow()
        } else {
            attempt.stop()
        }
    });
    reqwest::Client::builder()
        .redirect(policy)
        .connect_timeout(Duration::from_secs(20))
        .user_agent(concat!(
            "patchwatch-server/",
            env!("CARGO_PKG_VERSION"),
            " (+https://github.com/EinNiki/patchwatch)"
        ))
        .build()
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_kernel_comment_is_parsed_and_strict() {
        let c = "'linux-aws' kernel in noble was vulnerable but has been fixed (note: '6.8.0-1046.49').";
        assert_eq!(
            fixed_kernel(c, "noble"),
            Some(("linux-aws".into(), "6.8.0-1046.49".into()))
        );
        // anderes Release, kein Kernel-Paket, unsichere Zeichen, leere Version
        assert_eq!(fixed_kernel(c, "jammy"), None);
        assert_eq!(
            fixed_kernel(&c.replace("linux-aws", "openssl"), "noble"),
            None
        );
        assert_eq!(
            fixed_kernel(&c.replace("6.8.0-1046.49", "1;rm -rf"), "noble"),
            None
        );
        assert_eq!(fixed_kernel(&c.replace("6.8.0-1046.49", ""), "noble"), None);
        assert_eq!(fixed_kernel("Is kernel 'linux' running?", "noble"), None);
    }

    #[test]
    fn release_names_are_url_safe() {
        assert!(valid_release("noble"));
        assert!(valid_release("jammy"));
        for bad in ["", "../x", "No ble", "noble/", "a.b", "NOBLE"] {
            assert!(!valid_release(bad), "{bad}");
        }
        assert_eq!(
            file_url("https://x.example/oval/", "noble"),
            "https://x.example/oval/com.ubuntu.noble.cve.oval.xml.bz2"
        );
    }

    const FIXTURE: &str = include_str!("../../tests/fixtures/ubuntu/oval_noble_excerpt.xml");

    /// Echte Datei (verkürzt): nur behobene Kernel-Varianten, gruppiert je CVE, mit Fixversion.
    #[test]
    fn real_excerpt_yields_only_fixed_kernel_entries() {
        let recs = parse_cve_oval(FIXTURE.as_bytes(), "noble", 1 << 30).unwrap();
        let ids: Vec<&str> = recs.iter().map(|r| r.cve_id.as_str()).collect();
        // Nur CVEs mit mindestens einem behobenen Kernel-Eintrag; "Kernel läuft"-Fälle und fremde Pakete fehlen.
        assert!(ids.contains(&"CVE-2025-38250"), "{ids:?}");
        assert!(!ids.contains(&"CVE-2002-2439"), "kein Kernel-Eintrag");
        assert!(!ids.contains(&"CVE-2026-99999"), "kein Fixkriterium");
        let r = recs.iter().find(|r| r.cve_id == "CVE-2025-38250").unwrap();
        let linux = r.entries.iter().find(|e| e.package == "linux").unwrap();
        assert_eq!(linux.status, SourceStatus::Fixed);
        assert_eq!(linux.fix_version.as_deref(), Some("6.8.0-100.100"));
        assert!(r
            .entries
            .iter()
            .all(|e| e.release == "noble" && e.status == SourceStatus::Fixed));
        assert!(r.entries.iter().all(|e| e.package.starts_with("linux")));
        assert_eq!(r.priority.as_deref(), Some("low"));
        assert!(r.published_at.is_some());
        // Ein anderes Release liefert aus derselben Datei nichts (Kriterien nennen "noble").
        assert!(parse_cve_oval(FIXTURE.as_bytes(), "jammy", 1 << 30)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn truncated_or_oversized_input_is_an_error_never_a_partial_result() {
        let cut = &FIXTURE[..FIXTURE.len() / 2];
        assert!(
            parse_cve_oval(cut.as_bytes(), "noble", 1 << 30).is_err(),
            "abgeschnitten"
        );
        assert!(
            parse_cve_oval(FIXTURE.as_bytes(), "noble", 1000).is_err(),
            "über dem Limit"
        );
        assert!(parse_cve_oval(&b""[..], "noble", 1000).is_err(), "leer");
        assert!(parse_cve_oval(&b"kein xml <<<"[..], "noble", 1000).is_err());
    }

    #[test]
    fn capped_reader_rejects_oversized_input() {
        let mut r = Capped {
            inner: &b"0123456789"[..],
            left: 4,
        };
        let mut out = Vec::new();
        assert!(r.read_to_end(&mut out).is_err());
        let mut r = Capped {
            inner: &b"0123"[..],
            left: 4,
        };
        let mut out = Vec::new();
        assert_eq!(r.read_to_end(&mut out).unwrap(), 4);
    }
}
