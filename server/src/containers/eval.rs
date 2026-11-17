//! Bewertung eines Containers aus dem lokalen Stand und den Tatsachen der Registry. Reine Logik (keine Datenbank, kein
//! Netz); der Worker speichert die Tatsachen, diese Funktion macht daraus die Aussage für die Oberfläche.
//! Nichts wird geraten: fehlt eine Angabe, steht „nicht prüfbar“ mit Grund, nie ein stilles „aktuell“.
use super::reference::{self, Reference};
use super::tags::{self, Kind, Newest};
use serde::Serialize;

/// Was die Registry zu (Registry, Repository, Tag) gesagt hat.
#[derive(Debug, Clone, Default)]
pub struct Base {
    /// `ok`, `error` oder `deferred`.
    pub status: String,
    pub error: Option<String>,
    pub registry_digest: Option<String>,
    /// `index` oder `manifest`.
    pub manifest_kind: Option<String>,
    pub newest: Newest,
    pub tags_incomplete: bool,
}

/// Das Manifest der Host-Plattform (nur bei Indexen, nur wenn der Index-Digest vom lokalen abwich).
#[derive(Debug, Clone, Default)]
pub struct PlatformFacts {
    pub status: String,
    pub config_digest: Option<String>,
}

/// Lokaler Stand eines Containers.
pub struct Local<'a> {
    pub image_ref: &'a str,
    pub image_id: &'a str,
    pub repo_digests: &'a [String],
}

#[derive(Debug, PartialEq, Eq, Serialize, Clone)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Verdict {
    /// Mit Digest festgelegt: bewusst nicht beweglich (nur Information).
    Pinned,
    /// Registry nicht in der Positivliste oder Referenz nicht lesbar.
    Unsupported,
    /// Noch nicht geprüft.
    Pending,
    /// Die Prüfung wurde wegen des Abruflimits verschoben.
    Deferred,
    Error {
        text: String,
    },
    Current,
    /// Neuerer Stand unter demselben (gleitenden) Tag. `platform_confirmed`: der Stand für die Plattform des Hosts wurde
    /// verglichen; sonst weicht nur der Digest ab (andere Plattformen könnten die Ursache sein).
    UpdateAvailable {
        platform_confirmed: bool,
    },
    /// Neuere feste Version; getrennt nach Art des Sprungs.
    NewerVersion {
        patch: Option<String>,
        minor: Option<String>,
        major: Option<String>,
    },
    /// Tag ist kein sicher vergleichbares Versionsformat (Datum, Hash, Vorabversion).
    Incomparable,
    /// Tag-Liste der Registry unvollständig: kein Urteil.
    Incomplete,
    /// Lokal kein Registry-Digest bekannt (lokal gebaut oder nie gezogen).
    NoLocalDigest,
}

impl Verdict {
    /// Zeigt es einen neueren Stand an?
    pub fn is_update(&self) -> bool {
        matches!(
            self,
            Self::UpdateAvailable { .. } | Self::NewerVersion { .. }
        )
    }
}

fn digest_part(repo_digest: &str) -> &str {
    repo_digest.rsplit_once('@').map_or(repo_digest, |(_, d)| d)
}

pub fn evaluate(
    local: &Local<'_>,
    base: Option<&Base>,
    platform: Option<&PlatformFacts>,
) -> Verdict {
    let Some(r) = reference::parse(local.image_ref) else {
        return Verdict::Unsupported;
    };
    verdict_for(&r, local, base, platform)
}

fn verdict_for(
    r: &Reference,
    local: &Local<'_>,
    base: Option<&Base>,
    platform: Option<&PlatformFacts>,
) -> Verdict {
    if r.digest.is_some() {
        return Verdict::Pinned;
    }
    if !r.supported() {
        return Verdict::Unsupported;
    }
    let tag = r.tag.as_deref().unwrap_or("latest");
    let kind = tags::classify(tag);
    if kind == Kind::Incomparable {
        return Verdict::Incomparable;
    }
    let Some(base) = base else {
        return Verdict::Pending;
    };
    match base.status.as_str() {
        "deferred" => return Verdict::Deferred,
        "ok" => {}
        _ => {
            return Verdict::Error {
                text: base
                    .error
                    .clone()
                    .unwrap_or_else(|| "Prüfung fehlgeschlagen".into()),
            }
        }
    }
    match kind {
        Kind::Incomparable => Verdict::Incomparable,
        Kind::Fixed(_) => {
            let n = &base.newest;
            if n.patch.is_some() || n.minor.is_some() || n.major.is_some() {
                Verdict::NewerVersion {
                    patch: n.patch.clone(),
                    minor: n.minor.clone(),
                    major: n.major.clone(),
                }
            } else if base.tags_incomplete {
                Verdict::Incomplete
            } else {
                Verdict::Current
            }
        }
        Kind::Floating => {
            let Some(reg) = base.registry_digest.as_deref() else {
                return Verdict::Pending;
            };
            if local
                .repo_digests
                .iter()
                .map(|d| digest_part(d))
                .next()
                .is_none()
            {
                return Verdict::NoLocalDigest;
            }
            if local.repo_digests.iter().any(|d| digest_part(d) == reg) {
                return Verdict::Current;
            }
            if base.manifest_kind.as_deref() == Some("index") {
                return match platform {
                    Some(p)
                        if p.status == "ok"
                            && p.config_digest
                                .as_deref()
                                .is_some_and(|c| c == local.image_id) =>
                    {
                        Verdict::Current
                    }
                    Some(p) if p.status == "ok" && p.config_digest.is_some() => {
                        Verdict::UpdateAvailable {
                            platform_confirmed: true,
                        }
                    }
                    _ => Verdict::UpdateAvailable {
                        platform_confirmed: false,
                    },
                };
            }
            Verdict::UpdateAvailable {
                platform_confirmed: true,
            }
        }
    }
}

/// Befehl zum Kopieren (nur Text, wird nie ausgeführt). `None`, wenn der Dienstname fehlt oder nicht sicher ist.
pub fn compose_command(service: Option<&str>) -> Option<String> {
    let s = service.filter(|s| super::intake::valid_compose_name(s))?;
    Some(format!(
        "docker compose pull {s} && docker compose up -d {s}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const D1: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const D2: &str = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    const CFG: &str = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn local<'a>(image: &'a str, digests: &'a [String], id: &'a str) -> Local<'a> {
        Local {
            image_ref: image,
            image_id: id,
            repo_digests: digests,
        }
    }
    fn ok_base(digest: &str, kind: &str) -> Base {
        Base {
            status: "ok".into(),
            registry_digest: Some(digest.into()),
            manifest_kind: Some(kind.into()),
            ..Base::default()
        }
    }

    #[test]
    fn floating_tag_with_the_same_digest_is_current() {
        let d = vec![format!("nginx@{D1}")];
        assert_eq!(
            evaluate(
                &local("nginx:latest", &d, CFG),
                Some(&ok_base(D1, "index")),
                None
            ),
            Verdict::Current
        );
    }

    #[test]
    fn a_different_digest_on_a_single_manifest_is_an_update_for_that_platform() {
        let d = vec![format!("nginx@{D1}")];
        assert_eq!(
            evaluate(
                &local("nginx", &d, CFG),
                Some(&ok_base(D2, "manifest")),
                None
            ),
            Verdict::UpdateAvailable {
                platform_confirmed: true
            }
        );
    }

    #[test]
    fn index_differs_but_the_platform_image_is_unchanged_means_current() {
        let d = vec![format!("nginx@{D1}")];
        let p = PlatformFacts {
            status: "ok".into(),
            config_digest: Some(CFG.into()),
        };
        assert_eq!(
            evaluate(
                &local("nginx:latest", &d, CFG),
                Some(&ok_base(D2, "index")),
                Some(&p)
            ),
            Verdict::Current
        );
    }

    #[test]
    fn index_differs_and_the_platform_image_changed_is_a_confirmed_update() {
        let d = vec![format!("nginx@{D1}")];
        let p = PlatformFacts {
            status: "ok".into(),
            config_digest: Some(D2.into()),
        };
        assert_eq!(
            evaluate(
                &local("nginx:latest", &d, CFG),
                Some(&ok_base(D2, "index")),
                Some(&p)
            ),
            Verdict::UpdateAvailable {
                platform_confirmed: true
            }
        );
    }

    #[test]
    fn index_differs_without_platform_detail_says_only_that_the_digest_differs() {
        let d = vec![format!("nginx@{D1}")];
        assert_eq!(
            evaluate(
                &local("nginx:latest", &d, CFG),
                Some(&ok_base(D2, "index")),
                None
            ),
            Verdict::UpdateAvailable {
                platform_confirmed: false
            }
        );
        let failed = PlatformFacts {
            status: "error".into(),
            config_digest: None,
        };
        assert_eq!(
            evaluate(
                &local("nginx:latest", &d, CFG),
                Some(&ok_base(D2, "index")),
                Some(&failed)
            ),
            Verdict::UpdateAvailable {
                platform_confirmed: false
            }
        );
    }

    #[test]
    fn fixed_versions_report_patch_minor_and_major_apart() {
        let d: Vec<String> = vec![];
        let mut b = Base {
            status: "ok".into(),
            ..Base::default()
        };
        assert_eq!(
            evaluate(&local("postgres:17.2.1", &d, CFG), Some(&b), None),
            Verdict::Current
        );
        b.newest = Newest {
            patch: Some("17.2.4".into()),
            minor: None,
            major: Some("18.0.1".into()),
        };
        assert_eq!(
            evaluate(&local("postgres:17.2.1", &d, CFG), Some(&b), None),
            Verdict::NewerVersion {
                patch: Some("17.2.4".into()),
                minor: None,
                major: Some("18.0.1".into())
            }
        );
        // Unvollständige Liste und nichts Neueres gefunden: nie ein grünes „aktuell“.
        b.newest = Newest::default();
        b.tags_incomplete = true;
        assert_eq!(
            evaluate(&local("postgres:17.2.1", &d, CFG), Some(&b), None),
            Verdict::Incomplete
        );
    }

    #[test]
    fn special_cases_never_claim_current() {
        let d = vec![format!("x@{D1}")];
        let pin = format!("ghcr.io/a/b@{D1}");
        assert_eq!(evaluate(&local(&pin, &d, CFG), None, None), Verdict::Pinned);
        assert_eq!(
            evaluate(
                &local("mcr.microsoft.com/dotnet/aspnet:8.0", &d, CFG),
                None,
                None
            ),
            Verdict::Unsupported
        );
        assert_eq!(
            evaluate(
                &local("registry.example.org:5000/app:1", &d, CFG),
                None,
                None
            ),
            Verdict::Unsupported
        );
        assert_eq!(
            evaluate(&local("nginx:20240101.1.2", &d, CFG), None, None),
            Verdict::Incomparable
        );
        assert_eq!(
            evaluate(&local("nginx:1.2.3-rc1", &d, CFG), None, None),
            Verdict::Incomparable
        );
        assert_eq!(
            evaluate(&local("nginx:latest", &d, CFG), None, None),
            Verdict::Pending
        );
        assert_eq!(
            evaluate(&local("", &d, CFG), None, None),
            Verdict::Unsupported
        );
        let deferred = Base {
            status: "deferred".into(),
            ..Base::default()
        };
        assert_eq!(
            evaluate(&local("nginx:latest", &d, CFG), Some(&deferred), None),
            Verdict::Deferred
        );
        let err = Base {
            status: "error".into(),
            error: Some("Registry nicht erreichbar".into()),
            ..Base::default()
        };
        assert_eq!(
            evaluate(&local("nginx:latest", &d, CFG), Some(&err), None),
            Verdict::Error {
                text: "Registry nicht erreichbar".into()
            }
        );
        // Lokal gebaut (keine Digests): kein Urteil über „aktuell“.
        assert_eq!(
            evaluate(
                &local("nginx:latest", &[], CFG),
                Some(&ok_base(D1, "manifest")),
                None
            ),
            Verdict::NoLocalDigest
        );
    }

    #[test]
    fn only_updates_count_as_updates() {
        assert!(Verdict::UpdateAvailable {
            platform_confirmed: false
        }
        .is_update());
        assert!(Verdict::NewerVersion {
            patch: None,
            minor: None,
            major: Some("2".into())
        }
        .is_update());
        for v in [
            Verdict::Current,
            Verdict::Pinned,
            Verdict::Pending,
            Verdict::Incomplete,
            Verdict::Incomparable,
            Verdict::Unsupported,
        ] {
            assert!(!v.is_update());
        }
    }

    #[test]
    fn the_command_text_is_built_only_from_a_safe_service_name() {
        assert_eq!(
            compose_command(Some("web")).as_deref(),
            Some("docker compose pull web && docker compose up -d web")
        );
        assert!(compose_command(Some("db_1.x-y")).is_some());
        for bad in [
            "",
            "web; rm -rf /",
            "a b",
            "$(x)",
            "a`b`",
            "web\n",
            &"a".repeat(65),
        ] {
            assert_eq!(compose_command(Some(bad)), None, "{bad:?}");
        }
        assert_eq!(compose_command(None), None);
    }
}
