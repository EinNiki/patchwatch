//! Abfragen bei der Image-Registry (nur lesend, anonym). Positivliste: docker.io, ghcr.io, quay.io.
//!
//! Sicherheitsrahmen: feste Hosts (nichts aus Container-Daten wird zum Ziel), nur https, Adressprüfung und gepinnte
//! Auflösung über `notify::ssrf`, keine Weiterleitungen, Antworten begrenzt, höchstens eine Anfrage gleichzeitig je
//! Registry. Fehlertexte enthalten nie Antwortinhalte.
//!
//! Abrufzählung (Docker Hub): `HEAD` auf ein Manifest zählt nicht auf das Pull-Limit, jedes `GET` schon; für `tags/list`
//! und den Token-Abruf gibt es keine Angabe, sie werden vorsichtshalber als zählend behandelt. Jede Sitzung zählt ihre
//! `GET`-Anfragen (`Session::gets`), der Worker begrenzt sie je Zeitfenster.
use crate::cve::http::{self, Limits};
use crate::cve::FeedError;
use crate::notify::ssrf;
use reqwest::{Client, Url};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

const MANIFEST_MAX: u64 = 1024 * 1024;
const TAGS_MAX: u64 = 4 * 1024 * 1024;
const TOKEN_MAX: u64 = 16 * 1024;
const TAG_PAGE: usize = 1000;
/// Mehr Seiten der Tag-Liste werden nicht abgerufen; ist sie dann nicht zu Ende, gilt sie als unvollständig.
const TAG_PAGES_MAX: usize = 5;
const ACCEPT_MANIFESTS: &str = "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, \
     application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json";

#[derive(Debug, PartialEq, Eq)]
pub enum RegError {
    NotFound,
    /// Anonymer Zugriff nicht möglich (privates Repository oder gesperrt).
    Unauthorized,
    Throttled {
        retry_after: Option<Duration>,
    },
    Http(u16),
    TooLarge,
    Network,
    /// Antwort hat nicht das erwartete Format.
    Format,
    /// Zieladresse gesperrt oder Registry nicht in der Positivliste.
    Blocked,
}

impl RegError {
    /// Klartext für die Oberfläche (kein Inhalt der Antwort).
    pub fn text(&self) -> String {
        match self {
            Self::NotFound => "Image oder Tag bei der Registry nicht gefunden".into(),
            Self::Unauthorized => "Kein anonymer Zugriff (privates Image?)".into(),
            Self::Throttled { .. } => {
                "Registry drosselt die Abfragen (HTTP 429/5xx), später erneut".into()
            }
            Self::Http(c) => format!("Registry antwortet mit HTTP {c}"),
            Self::TooLarge => "Antwort der Registry zu groß".into(),
            Self::Network => "Registry nicht erreichbar".into(),
            Self::Format => "Antwort der Registry nicht lesbar".into(),
            Self::Blocked => "Registry nicht erlaubt".into(),
        }
    }
}

fn convert(e: FeedError) -> RegError {
    match e {
        FeedError::Http(404) => RegError::NotFound,
        FeedError::Http(401 | 403) => RegError::Unauthorized,
        FeedError::Http(c) => RegError::Http(c),
        FeedError::Throttled { retry_after, .. } => RegError::Throttled { retry_after },
        FeedError::TooLarge(_) => RegError::TooLarge,
        FeedError::Format(_) => RegError::Format,
        _ => RegError::Network,
    }
}

/// Wohin und wie je Registry gesprochen wird.
#[derive(Clone)]
pub struct Endpoint {
    /// Basis der API, z. B. `https://registry-1.docker.io`.
    api: Url,
    /// Token-Adresse mit Platzhalter `{repo}` für das Repository.
    token: String,
}

fn production_endpoints() -> HashMap<&'static str, Endpoint> {
    let ep = |api: &str, token: &str| Endpoint {
        api: Url::parse(api).expect("feste Adresse"),
        token: token.to_owned(),
    };
    HashMap::from([
        ("docker.io", ep("https://registry-1.docker.io", "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull")),
        ("ghcr.io", ep("https://ghcr.io", "https://ghcr.io/token?scope=repository:{repo}:pull")),
        ("quay.io", ep("https://quay.io", "https://quay.io/v2/auth?service=quay.io&scope=repository:{repo}:pull")),
    ])
}

#[derive(Clone, Copy)]
enum Mode {
    /// Adressprüfung (SSRF) und gepinnte Auflösung; nur https.
    Production,
    /// Nur für Tests gegen einen lokalen Mock: ohne Adressprüfung.
    Plain,
}

#[derive(Clone)]
pub struct Registries {
    endpoints: Arc<HashMap<&'static str, Endpoint>>,
    /// Höchstens eine Anfrage gleichzeitig je Registry.
    gates: Arc<HashMap<&'static str, Arc<Semaphore>>>,
    mode: Mode,
    attempts: u32,
    base_delay: Duration,
    timeout: Duration,
}

impl Registries {
    pub fn production() -> Self {
        Self::with(
            production_endpoints(),
            Mode::Production,
            Duration::from_secs(2),
            Duration::from_secs(20),
        )
    }

    /// Test-Aufbau: alle drei Registrynamen zeigen auf denselben lokalen Mock (`http://127.0.0.1:PORT`).
    pub fn for_tests(base: &str) -> Self {
        let ep = Endpoint {
            api: Url::parse(base).expect("Mock-Adresse"),
            token: format!("{base}/token?scope=repository:{{repo}}:pull"),
        };
        let map = HashMap::from([
            ("docker.io", ep.clone()),
            ("ghcr.io", ep.clone()),
            ("quay.io", ep),
        ]);
        Self::with(
            map,
            Mode::Plain,
            Duration::from_millis(20),
            Duration::from_millis(600),
        )
    }

    fn with(
        endpoints: HashMap<&'static str, Endpoint>,
        mode: Mode,
        base_delay: Duration,
        timeout: Duration,
    ) -> Self {
        let gates = endpoints
            .keys()
            .map(|k| (*k, Arc::new(Semaphore::new(1))))
            .collect();
        Self {
            endpoints: Arc::new(endpoints),
            gates: Arc::new(gates),
            mode,
            attempts: 3,
            base_delay,
            timeout,
        }
    }

    /// Öffnet eine Sitzung (Token und Zähler) für ein Repository. Hält die Sperre der Registry, bis sie endet:
    /// parallele Prüfungen derselben Registry laufen nacheinander.
    pub async fn session(&self, registry: &str, repository: &str) -> Result<Session, RegError> {
        let (key, ep) = self
            .endpoints
            .get_key_value(registry)
            .ok_or(RegError::Blocked)?;
        let permit = self.gates[key]
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| RegError::Blocked)?;
        Ok(Session {
            reg: self.clone(),
            endpoint: ep.clone(),
            repository: repository.to_owned(),
            token: None,
            gets: 0,
            _permit: permit,
        })
    }

    async fn client_for(&self, url: &Url) -> Result<Client, RegError> {
        match self.mode {
            Mode::Plain => Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|_| RegError::Network),
            Mode::Production => {
                if url.scheme() != "https" {
                    return Err(RegError::Blocked);
                }
                // Keine Ausnahmeliste: eine Registry im internen Netz wird nie angefragt.
                let target = ssrf::resolve(url.clone(), &[])
                    .await
                    .map_err(|_| RegError::Blocked)?;
                ssrf::pinned_client(&target).map_err(|_| RegError::Network)
            }
        }
    }

    fn limits(&self, max_bytes: u64) -> Limits {
        Limits {
            max_bytes,
            timeout: self.timeout,
            attempts: self.attempts,
            base_delay: self.base_delay,
            retry_after_cap: Duration::from_secs(300),
        }
    }
}

pub struct Session {
    reg: Registries,
    endpoint: Endpoint,
    repository: String,
    token: Option<String>,
    /// Anzahl der `GET`-Anfragen dieser Sitzung (Token, Manifeste, Tag-Listen); `HEAD` zählt nicht.
    pub gets: u32,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Head {
    /// `Docker-Content-Digest` des Tags.
    pub digest: String,
    /// `index` (mehrere Plattformen) oder `manifest`.
    pub kind: &'static str,
}

#[derive(Debug, PartialEq, Eq)]
pub struct PlatformInfo {
    pub manifest_digest: String,
    pub config_digest: String,
}

fn is_digest(d: &str) -> bool {
    d.strip_prefix("sha256:")
        .is_some_and(|h| h.len() == 64 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

fn kind_of(media_type: &str) -> &'static str {
    let m = media_type.split(';').next().unwrap_or("").trim();
    if m.ends_with("image.index.v1+json") || m.ends_with("manifest.list.v2+json") {
        "index"
    } else {
        "manifest"
    }
}

#[derive(Deserialize)]
struct TokenBody {
    token: Option<String>,
    access_token: Option<String>,
}

#[derive(Deserialize)]
struct IndexBody {
    #[serde(default)]
    manifests: Vec<IndexEntry>,
}

#[derive(Deserialize)]
struct IndexEntry {
    digest: String,
    platform: Option<PlatformBody>,
}

#[derive(Deserialize)]
struct PlatformBody {
    os: Option<String>,
    architecture: Option<String>,
    variant: Option<String>,
}

#[derive(Deserialize)]
struct ManifestBody {
    config: Option<ConfigBody>,
}

#[derive(Deserialize)]
struct ConfigBody {
    digest: String,
}

#[derive(Deserialize)]
struct TagsBody {
    #[serde(default)]
    tags: Option<Vec<String>>,
}

impl Session {
    fn url(&self, path: &str) -> Result<Url, RegError> {
        self.endpoint.api.join(path).map_err(|_| RegError::Format)
    }

    fn repo_path(&self, tail: &str) -> String {
        format!("/v2/{}/{tail}", self.repository)
    }

    /// Anonymes Pull-Token (ein `GET`). Wird einmal je Sitzung geholt.
    async fn ensure_token(&mut self) -> Result<(), RegError> {
        if self.token.is_some() {
            return Ok(());
        }
        let url = Url::parse(&self.endpoint.token.replace("{repo}", &self.repository))
            .map_err(|_| RegError::Format)?;
        let client = self.reg.client_for(&url).await?;
        self.gets += 1;
        let got = http::get(
            &client,
            url.as_str(),
            &[("accept", "application/json")],
            self.reg.limits(TOKEN_MAX),
        )
        .await
        .map_err(convert)?;
        let body: TokenBody = serde_json::from_slice(&got.body).map_err(|_| RegError::Format)?;
        let t = body
            .token
            .or(body.access_token)
            .filter(|t| !t.is_empty() && t.len() <= 8192 && t.is_ascii())
            .ok_or(RegError::Format)?;
        self.token = Some(t);
        Ok(())
    }

    async fn call(
        &mut self,
        head: bool,
        path: &str,
        accept: &str,
        max: u64,
    ) -> Result<http::Fetched, RegError> {
        self.ensure_token().await?;
        let url = self.url(path)?;
        let client = self.reg.client_for(&url).await?;
        let bearer = format!("Bearer {}", self.token.as_deref().unwrap_or(""));
        if !head {
            self.gets += 1;
        }
        let limits = self.reg.limits(max);
        http::execute(
            || {
                let r = if head {
                    client.head(url.clone())
                } else {
                    client.get(url.clone())
                };
                r.header("authorization", &bearer).header("accept", accept)
            },
            limits,
        )
        .await
        .map_err(convert)
    }

    /// `HEAD /v2/<repo>/manifests/<tag>`: der Digest des Tags, ohne das Manifest zu laden (zählt nicht als Pull).
    pub async fn head_manifest(&mut self, tag: &str) -> Result<Head, RegError> {
        let got = self
            .call(
                true,
                &self.repo_path(&format!("manifests/{tag}")),
                ACCEPT_MANIFESTS,
                MANIFEST_MAX,
            )
            .await?;
        let digest = http::header_str(&got.headers, "docker-content-digest")
            .filter(|d| is_digest(d))
            .ok_or(RegError::Format)?;
        let kind = kind_of(&http::header_str(&got.headers, "content-type").unwrap_or_default());
        Ok(Head { digest, kind })
    }

    /// Bei einem Index: das Manifest der Plattform suchen (`GET` Index) und dessen Konfigurations-Digest lesen (`GET`
    /// Manifest). Gleicht er der lokalen Image-ID, ist das lokale Image aktuell. `None`, wenn der Index die Plattform nicht kennt.
    pub async fn platform_config(
        &mut self,
        index_digest: &str,
        os: &str,
        arch: &str,
        variant: Option<&str>,
    ) -> Result<Option<PlatformInfo>, RegError> {
        if !is_digest(index_digest) {
            return Err(RegError::Format);
        }
        let got = self
            .call(
                false,
                &self.repo_path(&format!("manifests/{index_digest}")),
                ACCEPT_MANIFESTS,
                MANIFEST_MAX,
            )
            .await?;
        let index: IndexBody = serde_json::from_slice(&got.body).map_err(|_| RegError::Format)?;
        let wanted = |p: &PlatformBody| {
            p.os.as_deref() == Some(os)
                && p.architecture.as_deref() == Some(arch)
                // Ohne Variante auf dem Host passt jeder Eintrag der Architektur; mit Variante muss sie stimmen.
                && variant.is_none_or(|v| p.variant.as_deref() == Some(v))
        };
        let Some(entry) = index
            .manifests
            .iter()
            .find(|m| m.platform.as_ref().is_some_and(wanted))
        else {
            return Ok(None);
        };
        if !is_digest(&entry.digest) {
            return Err(RegError::Format);
        }
        let got = self
            .call(
                false,
                &self.repo_path(&format!("manifests/{}", entry.digest)),
                ACCEPT_MANIFESTS,
                MANIFEST_MAX,
            )
            .await?;
        let m: ManifestBody = serde_json::from_slice(&got.body).map_err(|_| RegError::Format)?;
        let config = m
            .config
            .map(|c| c.digest)
            .filter(|d| is_digest(d))
            .ok_or(RegError::Format)?;
        Ok(Some(PlatformInfo {
            manifest_digest: entry.digest.clone(),
            config_digest: config,
        }))
    }

    /// Tag-Liste (`n=1000`, höchstens 5 Seiten). Der zweite Wert sagt, ob die Liste unvollständig ist (es gäbe weitere Seiten).
    pub async fn list_tags(&mut self) -> Result<(Vec<String>, bool), RegError> {
        let mut all: Vec<String> = Vec::new();
        let mut next = format!("{}?n={TAG_PAGE}", self.repo_path("tags/list"));
        for page in 0..TAG_PAGES_MAX {
            let got = self
                .call(false, &next, "application/json", TAGS_MAX)
                .await?;
            let body: TagsBody = serde_json::from_slice(&got.body).map_err(|_| RegError::Format)?;
            all.extend(body.tags.unwrap_or_default());
            match next_link(
                http::header_str(&got.headers, "link").as_deref(),
                &self.repository,
            ) {
                None => return Ok((all, false)),
                Some(n) if page + 1 == TAG_PAGES_MAX => {
                    let _ = n;
                    return Ok((all, true));
                }
                Some(n) => next = n,
            }
        }
        Ok((all, true))
    }
}

/// Nächste Seite aus `Link: </v2/<repo>/tags/list?last=x&n=1000>; rel="next"`. Es werden nur Pfade unter `/v2/<repo>/`
/// der eigenen Registry übernommen, nie ein fremder Host.
fn next_link(link: Option<&str>, repository: &str) -> Option<String> {
    let l = link?;
    let start = l.find('<')? + 1;
    let end = l[start..].find('>')? + start;
    if !l[end..].contains("rel=\"next\"") {
        return None;
    }
    let target = &l[start..end];
    let prefix = format!("/v2/{repository}/tags/list");
    (target.starts_with(&prefix) && !target.contains("://") && target.len() <= 512)
        .then(|| target.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_link_only_follows_paths_of_the_same_repository() {
        let l = |t: &str| format!("<{t}>; rel=\"next\"");
        assert_eq!(
            next_link(
                Some(&l("/v2/library/nginx/tags/list?last=1.9&n=1000")),
                "library/nginx"
            )
            .as_deref(),
            Some("/v2/library/nginx/tags/list?last=1.9&n=1000")
        );
        for bad in [
            "https://evil.example/v2/library/nginx/tags/list",
            "/v2/other/tags/list?last=x",
            "//evil.example/x",
            "/v2/library/nginx/tags/list/../../x?://",
        ] {
            assert_eq!(next_link(Some(&l(bad)), "library/nginx"), None, "{bad}");
        }
        assert_eq!(
            next_link(
                Some("</v2/library/nginx/tags/list?last=x>; rel=\"prev\""),
                "library/nginx"
            ),
            None
        );
        assert_eq!(next_link(None, "library/nginx"), None);
    }

    #[test]
    fn media_types_decide_between_index_and_manifest() {
        assert_eq!(kind_of("application/vnd.oci.image.index.v1+json"), "index");
        assert_eq!(
            kind_of("application/vnd.docker.distribution.manifest.list.v2+json; charset=utf-8"),
            "index"
        );
        assert_eq!(
            kind_of("application/vnd.docker.distribution.manifest.v2+json"),
            "manifest"
        );
        assert_eq!(kind_of(""), "manifest");
    }

    #[test]
    fn error_texts_never_contain_response_content() {
        for e in [
            RegError::NotFound,
            RegError::Unauthorized,
            RegError::Throttled { retry_after: None },
            RegError::Http(500),
            RegError::TooLarge,
            RegError::Network,
            RegError::Format,
            RegError::Blocked,
        ] {
            assert!(!e.text().is_empty());
        }
    }
}
