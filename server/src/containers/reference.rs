//! Image-Referenzen wie Docker sie versteht: `nginx` → `docker.io/library/nginx:latest`.

/// Registries, bei denen der Server nachfragt (Positivliste). Alles andere wird nicht geprüft.
pub const SUPPORTED: [&str; 3] = ["docker.io", "ghcr.io", "quay.io"];

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Reference {
    pub registry: String,
    pub repository: String,
    /// Fehlt, wenn die Referenz mit einem Digest festgelegt ist.
    pub tag: Option<String>,
    pub digest: Option<String>,
}

impl Reference {
    pub fn supported(&self) -> bool {
        SUPPORTED.contains(&self.registry.as_str())
    }
}

fn valid_component(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
        && s.starts_with(|c: char| c.is_ascii_alphanumeric())
}

fn valid_tag(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        && s.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
}

/// `None` bei allem, was keine gültige Referenz ist (leer, Großbuchstaben im Pfad, Leerzeichen, falscher Digest …).
pub fn parse(raw: &str) -> Option<Reference> {
    if raw.is_empty() || raw.len() > 255 {
        return None;
    }
    let (name_tag, digest) = match raw.split_once('@') {
        Some((n, d)) => {
            let ok = d.strip_prefix("sha256:").is_some_and(|h| {
                h.len() == 64 && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            });
            if !ok {
                return None;
            }
            (n, Some(d.to_owned()))
        }
        None => (raw, None),
    };
    // Der Tag steht nach dem letzten `:`, aber nur, wenn dahinter kein `/` mehr kommt (sonst ist es ein Port).
    let (name, tag) = match name_tag.rfind(':') {
        Some(i) if !name_tag[i + 1..].contains('/') => {
            (&name_tag[..i], Some(name_tag[i + 1..].to_owned()))
        }
        _ => (name_tag, None),
    };
    if tag.as_deref().is_some_and(|t| !valid_tag(t)) {
        return None;
    }
    let mut parts: Vec<&str> = name.split('/').collect();
    // Das erste Stück ist die Registry, wenn es wie ein Hostname aussieht (Punkt, Port) oder `localhost` ist.
    let first = parts[0];
    let is_registry =
        parts.len() > 1 && (first.contains('.') || first.contains(':') || first == "localhost");
    let mut registry = if is_registry {
        parts.remove(0).to_owned()
    } else {
        "docker.io".to_owned()
    };
    if matches!(
        registry.as_str(),
        "index.docker.io" | "registry-1.docker.io" | "registry.hub.docker.com"
    ) {
        registry = "docker.io".into();
    }
    let host_ok = registry.len() <= 128
        && registry
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '-' | ':'))
        && registry.starts_with(|c: char| c.is_ascii_alphanumeric())
        && !registry.contains("..");
    if !host_ok || parts.is_empty() || !parts.iter().all(|p| valid_component(p)) {
        return None;
    }
    if registry == "docker.io" && parts.len() == 1 {
        parts.insert(0, "library");
    }
    let tag = match (&tag, &digest) {
        (None, None) => Some("latest".to_owned()),
        _ => tag,
    };
    Some(Reference {
        registry,
        repository: parts.join("/"),
        tag,
        digest,
    })
}

/// Bezeichnung der Plattform eines Hosts für die Zwischenspeicherung, z. B. `linux/arm64/v8`.
pub fn platform(os: Option<&str>, arch: Option<&str>, variant: Option<&str>) -> Option<String> {
    let (os, arch) = (os?, arch?);
    Some(match variant {
        Some(v) if !v.is_empty() => format!("{os}/{arch}/{v}"),
        _ => format!("{os}/{arch}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(raw: &str) -> Reference {
        parse(raw).unwrap_or_else(|| panic!("{raw}"))
    }

    #[test]
    fn docker_hub_shortcuts_are_normalized_like_docker_does() {
        assert_eq!(
            r("nginx"),
            Reference {
                registry: "docker.io".into(),
                repository: "library/nginx".into(),
                tag: Some("latest".into()),
                digest: None
            }
        );
        assert_eq!(r("nginx:1.27").tag.as_deref(), Some("1.27"));
        assert_eq!(
            (
                r("grafana/grafana:11.2.0").repository.as_str(),
                r("grafana/grafana:11.2.0").registry.as_str()
            ),
            ("grafana/grafana", "docker.io")
        );
        assert_eq!(r("docker.io/library/redis:7").repository, "library/redis");
        assert_eq!(r("index.docker.io/library/redis:7").registry, "docker.io");
        assert_eq!(
            r("registry-1.docker.io/grafana/grafana").repository,
            "grafana/grafana"
        );
    }

    #[test]
    fn other_registries_keep_host_and_path() {
        let g = r("ghcr.io/einniki/patchwatch-server:0.2.2");
        assert_eq!(
            (g.registry.as_str(), g.repository.as_str(), g.tag.as_deref()),
            ("ghcr.io", "einniki/patchwatch-server", Some("0.2.2"))
        );
        assert!(g.supported());
        let q = r("quay.io/prometheus/node-exporter:v1.8.2");
        assert!(q.supported() && q.repository == "prometheus/node-exporter");
        let p = r("registry.example.org:5000/team/app:1.0");
        assert_eq!(
            (p.registry.as_str(), p.repository.as_str(), p.tag.as_deref()),
            ("registry.example.org:5000", "team/app", Some("1.0"))
        );
        assert!(!p.supported());
        assert!(!r("localhost/app").supported());
        assert!(!r("mcr.microsoft.com/dotnet/aspnet:8.0").supported());
    }

    #[test]
    fn digest_pins_have_no_tag_and_tag_plus_digest_keeps_both() {
        let d = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let pinned = r(&format!("ghcr.io/x/y@{d}"));
        assert_eq!((pinned.tag, pinned.digest.as_deref()), (None, Some(d)));
        let both = r(&format!("nginx:1.27@{d}"));
        assert_eq!(
            (both.tag.as_deref(), both.digest.as_deref()),
            (Some("1.27"), Some(d))
        );
    }

    #[test]
    fn a_port_is_not_a_tag() {
        let x = r("registry.example.org:5000/app");
        assert_eq!(
            (x.registry.as_str(), x.tag.as_deref()),
            ("registry.example.org:5000", Some("latest"))
        );
    }

    #[test]
    fn garbage_is_rejected() {
        for bad in [
            "",
            "NGINX",
            "nginx:",
            "nginx:a b",
            "nginx@sha256:zz",
            "nginx@md5:abc",
            "a//b",
            "ghcr.io/",
            "../etc",
            "ghcr.io/X/y",
            "nginx:-x",
            &"a".repeat(256),
        ] {
            assert!(parse(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn platform_names() {
        assert_eq!(
            platform(Some("linux"), Some("arm64"), Some("v8")).as_deref(),
            Some("linux/arm64/v8")
        );
        assert_eq!(
            platform(Some("linux"), Some("amd64"), None).as_deref(),
            Some("linux/amd64")
        );
        assert_eq!(platform(Some("linux"), None, None), None);
    }
}
