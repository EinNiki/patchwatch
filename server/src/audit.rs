//! Aktivitätsprotokoll (`audit_log`): nur feste Felder (Zeit, Akteur, Aktion, Ziel, Ergebnis, gekürzte Quell-IP).
//! Es nimmt absichtlich keine freien Datenstrukturen entgegen, damit nie ein Passwort, Token, Secret oder eine
//! Sitzungs-ID hineingelangt. Fehler beim Schreiben werden nur gezählt/gewarnt und stoppen die Aktion nicht.

use sqlx::PgPool;
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Ok,
    Denied,
    Failed,
}

impl Outcome {
    const fn key(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Denied => "denied",
            Self::Failed => "failed",
        }
    }
}

/// IPv4 auf /24, IPv6 auf /48 kürzen (Datenschutz; für die Zuordnung reicht das Netz).
pub fn shorten_ip(ip: &str) -> String {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            let o = v4.octets();
            format!("{}.{}.{}.0/24", o[0], o[1], o[2])
        }
        Ok(IpAddr::V6(v6)) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2])
        }
        Err(_) => "unbekannt".to_owned(),
    }
}

fn clip(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(max).collect()
}

/// Ein Ereignis eintragen. `action` ist eine feste Kennung (z. B. `user.created`), `target` der betroffene Benutzername.
pub async fn record(
    pool: &PgPool,
    actor_id: Option<i64>,
    actor_name: &str,
    action: &str,
    target: Option<&str>,
    outcome: Outcome,
    ip: &str,
) {
    let r = sqlx::query(
        "INSERT INTO audit_log (actor_id, actor_name, action, target, result, ip) VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(actor_id)
    .bind(clip(actor_name, 120))
    .bind(clip(action, 80))
    .bind(target.map(|t| clip(t, 200)))
    .bind(outcome.key())
    .bind(shorten_ip(ip))
    .execute(pool)
    .await;
    if let Err(e) = r {
        tracing::warn!(error = %e, "Aktivitätsprotokoll konnte nicht geschrieben werden");
    }
}

/// Einträge älter als `days` Tage entfernen.
pub async fn purge_older_than(pool: &PgPool, days: i64) -> sqlx::Result<u64> {
    Ok(
        sqlx::query("DELETE FROM audit_log WHERE at < now() - make_interval(days => $1::int)")
            .bind(days)
            .execute(pool)
            .await?
            .rows_affected(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ips_are_shortened() {
        assert_eq!(shorten_ip("203.0.113.77"), "203.0.113.0/24");
        assert_eq!(shorten_ip("2001:db8:1234:5678::1"), "2001:db8:1234::/48");
        assert_eq!(shorten_ip("unknown"), "unbekannt");
    }

    #[test]
    fn control_characters_never_enter_the_log() {
        assert_eq!(clip("a\nb\0c", 10), "abc");
        assert_eq!(clip("abcdef", 3), "abc");
    }
}
