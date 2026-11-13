//! Rollen und Rechte. Die Zuordnung ist fest im Code (keine eigenen Rollen). Jeder Handler, der Benutzerdaten liefert oder
//! ändert, verlangt ein benanntes Recht über die Extractor `Authed<P>` / `CsrfAuthed<P>` (siehe `extract.rs`); es gibt keinen
//! Extractor "angemeldet, aber ohne Recht" für Datenrouten. Rechte werden bei jeder Anfrage aus der Datenbank gelesen.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum Permission {
    HostsRead,
    HostsWrite,
    HostsDelete,
    HostsRun,
    AgentsTokens,
    CvesRead,
    CvesWatch,
    SourcesRead,
    SourcesWrite,
    SourcesRun,
    SourcesSecrets,
    ChannelsRead,
    ChannelsWrite,
    ChannelsTest,
    ChannelsSecrets,
    SettingsRead,
    SettingsWrite,
    UsersManage,
    OidcManage,
    AuditRead,
}

use Permission::*;

/// Alle Rechte (Reihenfolge = Anzeige in der Rechtevorschau).
pub const ALL: [Permission; 20] = [
    HostsRead,
    HostsWrite,
    HostsDelete,
    HostsRun,
    AgentsTokens,
    CvesRead,
    CvesWatch,
    SourcesRead,
    SourcesWrite,
    SourcesRun,
    SourcesSecrets,
    ChannelsRead,
    ChannelsWrite,
    ChannelsTest,
    ChannelsSecrets,
    SettingsRead,
    SettingsWrite,
    UsersManage,
    OidcManage,
    AuditRead,
];

impl Permission {
    /// Stabiler Name (API, Tests, Protokoll), z. B. `hosts.read`.
    pub const fn name(self) -> &'static str {
        match self {
            HostsRead => "hosts.read",
            HostsWrite => "hosts.write",
            HostsDelete => "hosts.delete",
            HostsRun => "hosts.run",
            AgentsTokens => "agents.tokens",
            CvesRead => "cves.read",
            CvesWatch => "cves.watch",
            SourcesRead => "sources.read",
            SourcesWrite => "sources.write",
            SourcesRun => "sources.run",
            SourcesSecrets => "sources.secrets",
            ChannelsRead => "channels.read",
            ChannelsWrite => "channels.write",
            ChannelsTest => "channels.test",
            ChannelsSecrets => "channels.secrets",
            SettingsRead => "settings.read",
            SettingsWrite => "settings.write",
            UsersManage => "users.manage",
            OidcManage => "oidc.manage",
            AuditRead => "audit.read",
        }
    }

    pub fn is_read(self) -> bool {
        self.name().ends_with(".read")
    }

    /// Umkehrung von [`name`]; unbekannte Namen (z. B. nach einer Umbenennung) liefern `None`.
    pub fn parse(name: &str) -> Option<Self> {
        ALL.iter().copied().find(|p| p.name() == name)
    }

    /// Rechte, die vorausgesetzt werden (Schreiben setzt Lesen voraus usw.). Die einzige Stelle für Abhängigkeiten.
    pub const fn requires(self) -> &'static [Permission] {
        match self {
            HostsWrite | HostsRun | AgentsTokens => &[HostsRead],
            HostsDelete => &[HostsWrite],
            CvesWatch => &[CvesRead],
            SourcesWrite | SourcesRun => &[SourcesRead],
            SourcesSecrets => &[SourcesWrite],
            ChannelsWrite | ChannelsTest => &[ChannelsRead],
            ChannelsSecrets => &[ChannelsWrite],
            SettingsWrite | OidcManage => &[SettingsRead],
            HostsRead | CvesRead | SourcesRead | ChannelsRead | SettingsRead | UsersManage
            | AuditRead => &[],
        }
    }

    /// Rechte, deren Vergabe das eigene Passwort bzw. eine frische Anmeldung verlangt.
    pub fn is_sensitive(self) -> bool {
        ADMIN_ONLY.contains(&self)
    }
}

/// Schließt eine Rechtemenge unter den Abhängigkeiten ab: ein Recht ohne seine Voraussetzung fällt weg (auch kaskadierend,
/// z. B. entfällt `hosts.delete`, sobald `hosts.read` fehlt). Ergebnis in der Reihenfolge von [`ALL`], ohne Doppelte.
pub fn close(set: &[Permission]) -> Vec<Permission> {
    let mut cur: Vec<Permission> = ALL.iter().copied().filter(|p| set.contains(p)).collect();
    loop {
        let keep: Vec<Permission> = cur
            .iter()
            .copied()
            .filter(|p| p.requires().iter().all(|r| cur.contains(r)))
            .collect();
        if keep.len() == cur.len() {
            return cur;
        }
        cur = keep;
    }
}

/// Wirksame Rechte eines Benutzers: ohne eigene Auswahl (`None`) die der Rolle (Vorlage), sonst die gespeicherten Namen.
/// Unbekannte Namen werden ignoriert (gelten als nicht gewährt, nie als Fehler und nie als erlaubt); die Menge wird
/// unter den Abhängigkeiten abgeschlossen.
pub fn effective(role: Role, stored: Option<&[String]>) -> Vec<Permission> {
    match stored {
        None => close(&role.permissions()),
        Some(names) => {
            let parsed: Vec<Permission> =
                names.iter().filter_map(|n| Permission::parse(n)).collect();
            close(&parsed)
        }
    }
}

/// `a` ist eine Teilmenge von `b`.
pub fn is_subset(a: &[Permission], b: &[Permission]) -> bool {
    a.iter().all(|p| b.contains(p))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Operator,
    Viewer,
}

pub const ROLES: [Role; 3] = [Role::Admin, Role::Operator, Role::Viewer];

/// Rechte, die nur Administratoren haben.
const ADMIN_ONLY: [Permission; 3] = [UsersManage, OidcManage, AuditRead];

impl Role {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "admin" => Some(Self::Admin),
            "operator" => Some(Self::Operator),
            "viewer" => Some(Self::Viewer),
            _ => None,
        }
    }

    /// Wert der Datenbankspalte `role`.
    pub const fn key(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Operator => "operator",
            Self::Viewer => "viewer",
        }
    }

    pub const fn title(self) -> &'static str {
        match self {
            Self::Admin => "Administrator",
            Self::Operator => "Betreiber",
            Self::Viewer => "Nur Lesen",
        }
    }

    pub fn allows(self, p: Permission) -> bool {
        match self {
            Self::Admin => true,
            Self::Operator => !ADMIN_ONLY.contains(&p),
            Self::Viewer => p.is_read() && !ADMIN_ONLY.contains(&p),
        }
    }

    pub fn permissions(self) -> Vec<Permission> {
        ALL.iter().copied().filter(|p| self.allows(*p)).collect()
    }
}

/// Typ-Marker je Recht für `Authed<P>`.
pub trait Perm: Send + Sync + 'static {
    const PERMISSION: Permission;
}

macro_rules! markers {
    ($($m:ident),* $(,)?) => {
        $(pub struct $m;
        impl super::Perm for $m { const PERMISSION: super::Permission = super::Permission::$m; })*
    };
}

/// Marker-Typen für `Authed<authz::p::HostsRead>` usw.
pub mod p {
    markers! {
        HostsRead, HostsWrite, HostsDelete, HostsRun, AgentsTokens, CvesRead, CvesWatch, SourcesRead, SourcesWrite,
        SourcesRun, SourcesSecrets, ChannelsRead, ChannelsWrite, ChannelsTest, ChannelsSecrets, SettingsRead, SettingsWrite, UsersManage, OidcManage, AuditRead,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_has_every_permission_and_names_are_unique() {
        assert_eq!(Role::Admin.permissions().len(), ALL.len());
        let mut names: Vec<_> = ALL.iter().map(|p| p.name()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), ALL.len());
    }

    #[test]
    fn operator_cannot_manage_users_oidc_or_read_the_audit_log() {
        for p in ADMIN_ONLY {
            assert!(!Role::Operator.allows(p), "{}", p.name());
            assert!(!Role::Viewer.allows(p), "{}", p.name());
        }
        assert!(
            Role::Operator.allows(SourcesWrite)
                && Role::Operator.allows(ChannelsTest)
                && Role::Operator.allows(HostsRun)
        );
    }

    #[test]
    fn viewer_has_read_rights_only() {
        for p in ALL {
            assert_eq!(
                Role::Viewer.allows(p),
                p.is_read() && !ADMIN_ONLY.contains(&p),
                "{}",
                p.name()
            );
        }
        assert!(
            Role::Viewer.allows(HostsRead)
                && !Role::Viewer.allows(SourcesRun)
                && !Role::Viewer.allows(ChannelsTest)
        );
    }

    #[test]
    fn every_role_key_round_trips() {
        for r in ROLES {
            assert_eq!(Role::parse(r.key()), Some(r));
        }
        assert_eq!(Role::parse("root"), None);
    }

    #[test]
    fn templates_are_closed_under_dependencies() {
        for r in ROLES {
            assert_eq!(close(&r.permissions()), r.permissions(), "{}", r.key());
        }
    }

    #[test]
    fn removing_a_read_right_drops_every_dependent_right() {
        let all = ALL.to_vec();
        let without: Vec<Permission> = all.iter().copied().filter(|p| *p != HostsRead).collect();
        let got = close(&without);
        for p in [HostsWrite, HostsDelete, HostsRun, AgentsTokens] {
            assert!(!got.contains(&p), "{} blieb stehen", p.name());
        }
        // kaskadierend: ohne sources.write fällt sources.secrets weg
        let got = close(&[SourcesRead, SourcesRun, SourcesSecrets]);
        assert_eq!(got, vec![SourcesRead, SourcesRun]);
        // unabhängige Rechte bleiben
        assert!(close(&without).contains(&CvesRead));
    }

    #[test]
    fn unknown_names_are_ignored_and_never_granted() {
        let names = vec![
            "hosts.read".to_owned(),
            "hosts.erase".to_owned(),
            "".to_owned(),
        ];
        assert_eq!(effective(Role::Admin, Some(&names)), vec![HostsRead]);
        // alles unbekannt: keine Rechte (nicht "wie die Rolle")
        assert!(effective(Role::Admin, Some(&["x.y".to_owned()])).is_empty());
        assert_eq!(effective(Role::Viewer, None), Role::Viewer.permissions());
    }

    #[test]
    fn every_dependency_is_listed_before_use_and_is_not_circular() {
        for p in ALL {
            for r in p.requires() {
                assert_ne!(*r, p);
                assert!(!r.requires().contains(&p));
            }
        }
    }

    #[test]
    fn subset_check() {
        assert!(is_subset(&[HostsRead], &[HostsRead, HostsWrite]));
        assert!(!is_subset(&[HostsWrite], &[HostsRead]));
    }
}
