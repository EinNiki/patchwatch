//! Docker-Container und ihre Images (nur auf ausdrücklichen Wunsch, `docker_enabled = true`).
//!
//! Datenschutz: Antworten von Docker werden nur in schmale Strukturen gelesen; alles andere (Umgebungsvariablen, Befehle,
//! Mounts, Netzwerke, fremde Labels, Ports) wird beim Parsen verworfen und kann deshalb nie im Bericht landen. Jeder Wert
//! wird zusätzlich auf erlaubte Zeichen und Länge geprüft.
use crate::docker_client::{DockerApi, DockerError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Obergrenze der gemeldeten Container (der Server akzeptiert dasselbe).
pub const MAX_CONTAINERS: usize = 500;
/// Obergrenze verschiedener Images, die einzeln nachgefragt werden.
const MAX_IMAGES: usize = 200;
const MAX_DIGESTS: usize = 8;

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct DockerReport {
    /// `ok` oder `unavailable`; fehlt der ganze Block im Bericht, ist Docker abgeschaltet.
    pub state: &'static str,
    /// Nur bei `unavailable`: `socket_missing`, `no_permission`, `timeout` oder `bad_response`.
    pub reason: Option<&'static str>,
    pub containers: Vec<Container>,
}

#[derive(Debug, Serialize, PartialEq, Eq, Clone)]
pub struct Container {
    /// Die ersten 12 Zeichen der Container-ID.
    pub id: String,
    pub name: String,
    /// `running`, `exited`, `created`, `paused`, `restarting`, `dead` oder `removing`.
    pub state: String,
    pub created_unix: u64,
    /// Bereinigter Statustext („Up 3 hours“).
    pub status_text: String,
    /// Image-Angabe wie im Container eingetragen (z. B. `nginx:1.27`); leer, wenn sie nicht lesbar ist.
    pub image: String,
    pub image_id: String,
    pub repo_digests: Vec<String>,
    pub os: Option<String>,
    pub arch: Option<String>,
    pub variant: Option<String>,
    pub compose_project: Option<String>,
    pub compose_service: Option<String>,
}

#[derive(Deserialize)]
struct RawContainer {
    #[serde(rename = "Id", default)]
    id: String,
    #[serde(rename = "Names", default)]
    names: Option<Vec<String>>,
    #[serde(rename = "Image", default)]
    image: String,
    #[serde(rename = "ImageID", default)]
    image_id: String,
    #[serde(rename = "Created", default)]
    created: i64,
    #[serde(rename = "State", default)]
    state: String,
    #[serde(rename = "Status", default)]
    status: String,
    #[serde(rename = "Labels", default)]
    labels: Option<Labels>,
}

/// Nur diese beiden Labels werden gelesen; alle anderen fallen beim Parsen weg.
#[derive(Deserialize, Default)]
struct Labels {
    #[serde(rename = "com.docker.compose.project")]
    project: Option<String>,
    #[serde(rename = "com.docker.compose.service")]
    service: Option<String>,
}

#[derive(Deserialize)]
struct RawImage {
    #[serde(rename = "RepoDigests", default)]
    repo_digests: Option<Vec<String>>,
    #[serde(rename = "Os", default)]
    os: Option<String>,
    #[serde(rename = "Architecture", default)]
    arch: Option<String>,
    #[serde(rename = "Variant", default)]
    variant: Option<String>,
}

struct ImageInfo {
    digests: Vec<String>,
    os: Option<String>,
    arch: Option<String>,
    variant: Option<String>,
}

fn all_of(s: &str, ok: impl Fn(char) -> bool, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.chars().all(ok)
}

fn is_digest(d: &str) -> bool {
    d.strip_prefix("sha256:")
        .is_some_and(|h| h.len() == 64 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

/// Docker-Name eines Containers: `[A-Za-z0-9][A-Za-z0-9_.-]*`, höchstens 128 Zeichen.
fn clean_name(raw: &str) -> Option<String> {
    let n = raw.trim_start_matches('/');
    (all_of(
        n,
        |c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'),
        128,
    ) && n.starts_with(|c: char| c.is_ascii_alphanumeric()))
    .then(|| n.to_owned())
}

/// Image-Angabe (`registry/pfad:tag` oder `…@sha256:…`); sonst leer.
fn clean_image(raw: &str) -> String {
    let ok = all_of(
        raw,
        |c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | ':' | '@' | '-'),
        255,
    );
    if ok {
        raw.to_owned()
    } else {
        String::new()
    }
}

/// Compose-Name: `^[A-Za-z0-9._-]{1,64}$`.
fn clean_compose(raw: Option<&str>) -> Option<String> {
    raw.filter(|s| {
        all_of(
            s,
            |c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'),
            64,
        )
    })
    .map(str::to_owned)
}

/// Statustext wie „Up 3 hours (healthy)“: nur Buchstaben, Ziffern und wenige Satzzeichen, höchstens 64 Zeichen.
fn clean_status(raw: &str) -> String {
    raw.chars()
        .filter(|c| {
            c.is_ascii_alphanumeric() || matches!(c, ' ' | '(' | ')' | '.' | ',' | ':' | '-')
        })
        .take(64)
        .collect::<String>()
        .trim()
        .to_owned()
}

const STATES: [&str; 7] = [
    "running",
    "exited",
    "created",
    "paused",
    "restarting",
    "dead",
    "removing",
];

fn short(opt: Option<String>, max: usize) -> Option<String> {
    opt.filter(|s| {
        all_of(
            s,
            |c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'),
            max,
        )
    })
}

fn parse_containers(body: &[u8]) -> Result<Vec<RawContainer>, DockerError> {
    serde_json::from_slice(body).map_err(|_| DockerError::BadResponse)
}

fn parse_image(body: &[u8]) -> Option<ImageInfo> {
    let raw: RawImage = serde_json::from_slice(body).ok()?;
    let digests = raw
        .repo_digests
        .unwrap_or_default()
        .into_iter()
        .filter(|d| {
            d.rsplit_once('@').is_some_and(|(repo, dig)| {
                all_of(
                    repo,
                    |c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | ':' | '-'),
                    255,
                ) && is_digest(dig)
            })
        })
        .take(MAX_DIGESTS)
        .collect();
    Some(ImageInfo {
        digests,
        os: short(raw.os, 32),
        arch: short(raw.arch, 32),
        variant: short(raw.variant, 32),
    })
}

/// Liest Container und Images. Fehler werden zu `state = "unavailable"` mit festem Grund (nie Abbruch des Berichts).
pub fn collect(api: &dyn DockerApi) -> DockerReport {
    match gather(api) {
        Ok(containers) => DockerReport {
            state: "ok",
            reason: None,
            containers,
        },
        Err(e) => DockerReport {
            state: "unavailable",
            reason: Some(e.reason()),
            containers: Vec::new(),
        },
    }
}

fn gather(api: &dyn DockerApi) -> Result<Vec<Container>, DockerError> {
    let raw = parse_containers(&api.get("/containers/json?all=true")?)?;
    let mut images: HashMap<String, Option<ImageInfo>> = HashMap::new();
    let mut out = Vec::new();
    for c in raw.into_iter().take(MAX_CONTAINERS) {
        let Some(name) = c
            .names
            .as_deref()
            .and_then(|n| n.iter().find_map(|x| clean_name(x)))
        else {
            continue;
        };
        // Docker-IDs sind hexadezimal; alles andere ist kein Container, den wir melden.
        let id: String = c.id.chars().take(12).collect();
        if id.len() != 12 || !id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            continue;
        }
        let image_id = if is_digest(&c.image_id) {
            c.image_id.clone()
        } else {
            String::new()
        };
        if !image_id.is_empty() && !images.contains_key(&image_id) && images.len() < MAX_IMAGES {
            // Ein fehlendes Image ist kein Gesamtfehler: der Container erscheint ohne Digests.
            let info = api
                .get(&format!("/images/{image_id}/json"))
                .ok()
                .and_then(|b| parse_image(&b));
            images.insert(image_id.clone(), info);
        }
        let info = images.get(&image_id).and_then(Option::as_ref);
        let labels = c.labels.unwrap_or_default();
        out.push(Container {
            id: c
                .id
                .chars()
                .take(12)
                .filter(char::is_ascii_hexdigit)
                .collect(),
            name,
            state: if STATES.contains(&c.state.as_str()) {
                c.state
            } else {
                "unknown".into()
            },
            created_unix: u64::try_from(c.created).unwrap_or(0),
            status_text: clean_status(&c.status),
            image: clean_image(&c.image),
            image_id,
            repo_digests: info.map(|i| i.digests.clone()).unwrap_or_default(),
            os: info.and_then(|i| i.os.clone()),
            arch: info.and_then(|i| i.arch.clone()),
            variant: info.and_then(|i| i.variant.clone()),
            compose_project: clean_compose(labels.project.as_deref()),
            compose_service: clean_compose(labels.service.as_deref()),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    const CONTAINERS: &str = include_str!("../../tests/fixtures/docker-containers.json");
    const IMAGE: &str = include_str!("../../tests/fixtures/docker-image.json");

    /// Gefälschtes Docker: merkt sich jeden Pfad; Antworten je Pfad.
    struct Fake {
        seen: RefCell<Vec<String>>,
        containers: Result<&'static str, DockerError>,
    }
    impl DockerApi for Fake {
        fn get(&self, path: &str) -> Result<Vec<u8>, DockerError> {
            self.seen.borrow_mut().push(path.to_owned());
            assert!(
                crate::docker_client::allowed_path(path),
                "Pfad außerhalb der Positivliste: {path}"
            );
            if path.starts_with("/containers/") {
                return match &self.containers {
                    Ok(b) => Ok(b.as_bytes().to_vec()),
                    Err(DockerError::SocketMissing) => Err(DockerError::SocketMissing),
                    Err(DockerError::NoPermission) => Err(DockerError::NoPermission),
                    Err(DockerError::Timeout) => Err(DockerError::Timeout),
                    Err(_) => Err(DockerError::BadResponse),
                };
            }
            // Nur das erste Image ist bekannt; die anderen antworten wie ein Docker mit 404.
            if path.contains(&"a".repeat(64)) {
                Ok(IMAGE.as_bytes().to_vec())
            } else {
                Err(DockerError::BadResponse)
            }
        }
    }
    fn fake() -> Fake {
        Fake {
            seen: RefCell::new(Vec::new()),
            containers: Ok(CONTAINERS),
        }
    }

    #[test]
    fn reads_containers_images_and_compose_labels() {
        let f = fake();
        let r = collect(&f);
        assert_eq!((r.state, r.reason), ("ok", None));
        // Der vierte Container hat nur einen unbrauchbaren Namen (sha256:...) und wird übersprungen.
        assert_eq!(r.containers.len(), 3);
        let web = &r.containers[0];
        assert_eq!(
            (web.id.as_str(), web.name.as_str(), web.state.as_str()),
            ("b3f1c2d4e5f6", "web", "running")
        );
        assert_eq!(
            (
                web.image.as_str(),
                web.status_text.as_str(),
                web.created_unix
            ),
            ("nginx:1.27", "Up 3 hours (healthy)", 1_731_500_000)
        );
        assert_eq!(
            (
                web.compose_project.as_deref(),
                web.compose_service.as_deref()
            ),
            (Some("shop"), Some("web"))
        );
        assert_eq!(
            web.repo_digests,
            ["nginx@sha256:1111111111111111111111111111111111111111111111111111111111111111"]
        );
        assert_eq!(
            (
                web.os.as_deref(),
                web.arch.as_deref(),
                web.variant.as_deref()
            ),
            (Some("linux"), Some("arm64"), Some("v8"))
        );
        // Name: der erste gültige von mehreren Namen; Image ohne Digests, wenn Docker es nicht kennt.
        assert_eq!(r.containers[1].name, "shop-db-1");
        assert!(r.containers[1].repo_digests.is_empty() && r.containers[1].arch.is_none());
        assert_eq!(r.containers[2].compose_project, None);
        assert!(r.containers[2]
            .image
            .ends_with("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"));
    }

    #[test]
    fn nothing_but_the_allowed_fields_can_reach_the_report() {
        let json = serde_json::to_string(&collect(&fake())).unwrap();
        for secret in [
            "GEHEIM",
            "NETZ-GEHEIM",
            "intern.example.org",
            "traefik",
            "172.18",
            ".ssh",
            "/keys",
            "daemon off",
            "password",
            "DB_PASSWORD",
            "maintainer",
            "shop_default",
            "8080",
            "secret-label",
            "Mounts",
            "Env",
            "Cmd",
        ] {
            assert!(!json.contains(secret), "{secret} steht im Bericht: {json}");
        }
    }

    #[test]
    fn only_the_two_allowed_paths_are_requested_and_each_image_once() {
        let f = fake();
        collect(&f);
        let seen = f.seen.borrow();
        assert_eq!(seen[0], "/containers/json?all=true");
        let images: Vec<_> = seen.iter().filter(|p| p.starts_with("/images/")).collect();
        assert_eq!(images.len(), 3, "je Image einmal: {seen:?}");
    }

    #[test]
    fn failures_become_a_state_with_a_fixed_reason() {
        for (err, reason) in [
            (DockerError::SocketMissing, "socket_missing"),
            (DockerError::NoPermission, "no_permission"),
            (DockerError::Timeout, "timeout"),
            (DockerError::BadResponse, "bad_response"),
        ] {
            let f = Fake {
                seen: RefCell::new(Vec::new()),
                containers: Err(err),
            };
            let r = collect(&f);
            assert_eq!(
                (r.state, r.reason, r.containers.len()),
                ("unavailable", Some(reason), 0)
            );
        }
        // Antwort, die kein JSON-Array ist.
        let f = Fake {
            seen: RefCell::new(Vec::new()),
            containers: Ok("{\"message\":\"x\"}"),
        };
        assert_eq!(collect(&f).reason, Some("bad_response"));
    }

    #[test]
    fn hostile_values_are_dropped_or_cleaned() {
        let body = r#"[{"Id":"0123456789abcdef","Names":["/ok-name"],"Image":"evil image;rm -rf","ImageID":"nope","Created":-5,
          "State":"<b>x</b>","Status":"Up <b>3</b> hours\nERROR","Labels":{"com.docker.compose.project":"a b","com.docker.compose.service":"web;x"}},
          {"Id":"zz<script>","Names":["/ok2"],"Image":"x","ImageID":"","Created":1,"State":"running","Status":"Up"},
          {"Id":"0123456789abcdef","Names":["/../etc"],"Image":"x","ImageID":"","Created":1,"State":"running","Status":"Up"}]"#;
        let f = Fake {
            seen: RefCell::new(Vec::new()),
            containers: Ok(Box::leak(body.to_owned().into_boxed_str())),
        };
        let r = collect(&f);
        assert_eq!(r.containers.len(), 1);
        let c = &r.containers[0];
        assert_eq!(
            (
                c.id.as_str(),
                c.state.as_str(),
                c.image.as_str(),
                c.image_id.as_str(),
                c.created_unix
            ),
            ("0123456789ab", "unknown", "", "", 0)
        );
        assert_eq!(c.status_text, "Up b3b hoursERROR");
        assert_eq!(
            (c.compose_project.as_deref(), c.compose_service.as_deref()),
            (None, None)
        );
        assert!(
            f.seen.borrow().iter().all(|p| !p.starts_with("/images/")),
            "ungültige Image-ID wird nicht nachgefragt"
        );
    }

    #[test]
    fn at_most_500_containers_are_reported() {
        let many: Vec<String> = (0..600)
            .map(|i| format!(r#"{{"Id":"{i:012x}","Names":["/c{i}"],"Image":"x","ImageID":"","Created":1,"State":"running","Status":"Up"}}"#))
            .collect();
        let body: &'static str = Box::leak(format!("[{}]", many.join(",")).into_boxed_str());
        let r = collect(&Fake {
            seen: RefCell::new(Vec::new()),
            containers: Ok(body),
        });
        assert_eq!(r.containers.len(), MAX_CONTAINERS);
    }
}
