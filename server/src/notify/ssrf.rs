//! SSRF-Schutz für ausgehende Aufrufe der Benachrichtigungskanäle.
//!
//! * nur `http`/`https`, keine Zugangsdaten in der URL
//! * der Hostname wird aufgelöst, **jede** Adresse wird geprüft, und die Verbindung wird auf die
//!   geprüften Adressen festgelegt (kein zweites DNS-Lookup beim Verbinden: Schutz vor DNS-Rebinding)
//! * Loopback und Link-Local (169.254.0.0/16 inkl. Metadaten-IP 169.254.169.254, fe80::/10) sind immer
//!   gesperrt, auch für Hosts auf der Allowlist
//! * private/nicht-öffentliche Adressen nur, wenn der Host **exakt** in `notify_allowed_hosts` steht
//! * keine Redirects, Timeouts, die Antwort wird nie gelesen oder weitergegeben

use reqwest::Url;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_URL_LEN: usize = 2048;

#[derive(Debug, PartialEq, Eq)]
pub enum UrlError {
    Invalid(&'static str),
    /// Zieladresse ist nicht erlaubt (intern, Loopback, Link-Local …).
    Blocked,
    /// Name nicht auflösbar oder Zeitüberschreitung.
    Unresolvable,
}

impl UrlError {
    pub fn message(&self) -> &'static str {
        match self {
            Self::Invalid(m) => m,
            Self::Blocked => "Zieladresse ist nicht erlaubt (interne oder gesperrte Adresse)",
            Self::Unresolvable => "Host nicht auflösbar",
        }
    }
}

/// Syntaktische Prüfung (ohne Netzwerk). `allow_query` ist für Geheimnis-URLs (Webhooks) gedacht.
pub fn parse_url(raw: &str, allow_query: bool) -> Result<Url, UrlError> {
    if raw.is_empty() || raw.len() > MAX_URL_LEN || raw.chars().any(char::is_control) {
        return Err(UrlError::Invalid(
            "URL ist leer, zu lang oder enthält Steuerzeichen",
        ));
    }
    let url = Url::parse(raw.trim()).map_err(|_| UrlError::Invalid("keine gültige URL"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(UrlError::Invalid("nur http:// und https:// sind erlaubt"));
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err(UrlError::Invalid("URL ohne Host"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(UrlError::Invalid("URL darf keine Zugangsdaten enthalten"));
    }
    if url.fragment().is_some() || (!allow_query && url.query().is_some()) {
        return Err(UrlError::Invalid(
            "URL darf keine Query und kein Fragment enthalten (Zugangsdaten gehören in das Geheimnis-Feld)",
        ));
    }
    Ok(url)
}

/// Zieladresse mit eingebettetem IPv4 (IPv4-mapped/-compatible, NAT64, 6to4) auf die IPv4 zurückführen.
fn embedded_v4(ip: &Ipv6Addr) -> Option<Ipv4Addr> {
    let o = ip.octets();
    if let Some(v4) = ip.to_ipv4() {
        // ::ffff:a.b.c.d und ::a.b.c.d (ohne ::1 und ::)
        if !ip.is_loopback() && !ip.is_unspecified() {
            return Some(v4);
        }
    }
    // NAT64 64:ff9b::/96
    if o[..12] == [0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0] {
        return Some(Ipv4Addr::new(o[12], o[13], o[14], o[15]));
    }
    // 6to4 2002::/16
    if o[0] == 0x20 && o[1] == 0x02 {
        return Some(Ipv4Addr::new(o[2], o[3], o[4], o[5]));
    }
    None
}

fn v4_always_blocked(ip: Ipv4Addr) -> bool {
    ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.octets()[0] == 0
}

fn v6_always_blocked(ip: &Ipv6Addr) -> bool {
    let s = ip.segments();
    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (s[0] & 0xffc0) == 0xfe80 // fe80::/10 link-local
        // AWS-IPv6-Metadatendienst fd00:ec2::254 liegt im ULA-Bereich und bleibt deshalb ausdrücklich gesperrt.
        || (s[0] == 0xfd00 && s[1] == 0x0ec2)
}

/// Immer gesperrt, auch bei Allowlist: Loopback, Link-Local, unspezifiziert, Multicast/Broadcast.
pub fn always_blocked(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4_always_blocked(v4),
        IpAddr::V6(v6) => v6_always_blocked(&v6) || embedded_v4(&v6).is_some_and(v4_always_blocked),
    }
}

fn v4_global(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_private()
        || ip.is_documentation()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || ip.is_multicast()
        || o[0] == 0 // 0.0.0.0/8
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64.0.0/10 CGNAT
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24
        || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18.0.0/15 Benchmarks
        || o[0] >= 240) // 240.0.0.0/4 reserviert
}

fn v6_global(ip: &Ipv6Addr) -> bool {
    if let Some(v4) = embedded_v4(ip) {
        return v4_global(v4);
    }
    let s = ip.segments();
    // Nur 2000::/3 (globale Unicast-Adressen), ohne Dokumentation und Teredo.
    (s[0] & 0xe000) == 0x2000
        && !(s[0] == 0x2001 && (s[1] == 0x0db8 || s[1] == 0))
        && !ip.is_loopback()
}

/// Öffentlich routbare Adresse (alles andere gilt als intern).
pub fn is_global(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4_global(v4),
        IpAddr::V6(v6) => v6_global(&v6),
    }
}

/// Entscheidet für eine aufgelöste Adresse. `allowed` = Host steht exakt in der Allowlist.
pub fn check_addr(ip: IpAddr, allowed: bool) -> Result<(), UrlError> {
    if always_blocked(ip) {
        return Err(UrlError::Blocked);
    }
    if is_global(ip) || allowed {
        Ok(())
    } else {
        Err(UrlError::Blocked)
    }
}

/// Ein geprüftes Ziel: URL, Hostname und die Adressen, auf die verbunden werden darf.
#[derive(Debug)]
pub struct Target {
    pub url: Url,
    pub host: String,
    pub addrs: Vec<SocketAddr>,
}

/// Exakter Vergleich des URL-Hosts mit der Allowlist (Kleinschreibung, IPv6 ohne Klammern).
fn host_allowed(host: &str, allowed_hosts: &[String]) -> bool {
    let h = host.trim_matches(['[', ']']).to_ascii_lowercase();
    allowed_hosts
        .iter()
        .any(|a| a.trim_matches(['[', ']']) == h)
}

/// Löst den Host auf und prüft alle Adressen. Fehlerhafte Auflösung ist ein Fehler, nie ein Freibrief.
pub async fn resolve(url: Url, allowed_hosts: &[String]) -> Result<Target, UrlError> {
    let host = url
        .host_str()
        .ok_or(UrlError::Invalid("URL ohne Host"))?
        .to_owned();
    let port = url
        .port_or_known_default()
        .ok_or(UrlError::Invalid("unbekannter Port"))?;
    let allowed = host_allowed(&host, allowed_hosts);
    let ips: Vec<IpAddr> = match host.trim_matches(['[', ']']).parse::<IpAddr>() {
        Ok(ip) => vec![ip],
        Err(_) => tokio::time::timeout(
            RESOLVE_TIMEOUT,
            tokio::net::lookup_host((host.as_str(), port)),
        )
        .await
        .map_err(|_| UrlError::Unresolvable)?
        .map_err(|_| UrlError::Unresolvable)?
        .map(|a| a.ip())
        .collect(),
    };
    if ips.is_empty() {
        return Err(UrlError::Unresolvable);
    }
    for ip in &ips {
        check_addr(*ip, allowed)?;
    }
    Ok(Target {
        url,
        host,
        addrs: ips
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect(),
    })
}

/// HTTP-Client, der nur zu den geprüften Adressen verbindet und keinen Redirect folgt.
///
/// `.no_proxy()`: reqwest läse sonst `HTTP(S)_PROXY`/`ALL_PROXY` aus der Umgebung und schickte die Anfrage an den Proxy
/// statt an die geprüfte, gepinnte IP; Adressprüfung und Rebinding-Schutz wären dann wirkungslos (Fund 6).
pub fn pinned_client(target: &Target) -> reqwest::Result<reqwest::Client> {
    let mut b = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .user_agent(concat!("patchwatch-server/", env!("CARGO_PKG_VERSION")));
    // Für Namen die geprüften Adressen festschreiben; IP-Literale brauchen keine Auflösung.
    if target
        .host
        .trim_matches(['[', ']'])
        .parse::<IpAddr>()
        .is_err()
    {
        b = b.resolve_to_addrs(&target.host, &target.addrs);
    }
    b.build()
}

/// Client für vertrauenswürdige Ziele (Allowlist des Betreibers, keine Adressprüfung): ohne Redirects und ebenfalls
/// ohne Umgebungs-Proxy, damit ein gesetzter Proxy nicht unbemerkt neue Wege öffnet.
pub fn trusted_client() -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn url_syntax() {
        assert!(parse_url("https://ntfy.sh", false).is_ok());
        assert!(parse_url("http://gotify.lan:8080/base", false).is_ok());
        for bad in [
            "",
            "ftp://x.example",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "https://user:pw@x.example",
            "https://user@x.example",
            "https://x.example/#frag",
            "https://x.example/?token=geheim",
            "//x.example",
            "https://",
            "https://x.example/\n",
        ] {
            assert!(
                parse_url(bad, false).is_err(),
                "{bad:?} muss abgelehnt werden"
            );
        }
        // Webhook-URLs (Geheimnis) dürfen eine Query tragen.
        assert!(parse_url("https://discord.com/api/webhooks/1/abc?wait=true", true).is_ok());
        assert!(parse_url(&format!("https://x.example/{}", "a".repeat(3000)), false).is_err());
    }

    #[test]
    fn public_addresses_are_allowed_without_allowlist() {
        for a in [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "2606:4700:4700::1111",
            "2a00:1450:4001::200e",
        ] {
            assert!(check_addr(ip(a), false).is_ok(), "{a}");
        }
    }

    #[test]
    fn internal_addresses_need_the_allowlist() {
        for a in [
            "10.0.0.5",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.10",
            "100.64.0.1",
            "100.127.255.254",
            "192.0.0.8",
            "198.18.0.1",
            "198.19.255.255",
            "192.0.2.1",
            "198.51.100.7",
            "203.0.113.9",
            "240.0.0.1",
            "fd12:3456::1",
            "fc00::1",
            "2001:db8::1",
            "2001::1",
            "fec0::1",
        ] {
            assert_eq!(
                check_addr(ip(a), false),
                Err(UrlError::Blocked),
                "{a} ohne Allowlist"
            );
            assert!(check_addr(ip(a), true).is_ok(), "{a} mit Allowlist");
        }
    }

    #[test]
    fn loopback_and_link_local_are_blocked_even_with_allowlist() {
        for a in [
            "127.0.0.1",
            "127.1.2.3",
            "::1",
            "0.0.0.0",
            "::",
            "169.254.169.254",
            "169.254.0.1",
            "169.254.255.255",
            "fe80::1",
            "febf::1",
            "fd00:ec2::254",
            "255.255.255.255",
            "224.0.0.1",
            "ff02::1",
            "0.1.2.3",
            // eingebettete IPv4
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "::127.0.0.1",
            "64:ff9b::7f00:1",
            "64:ff9b::a9fe:a9fe",
            "2002:7f00:1::1",
            "2002:a9fe:a9fe::1",
        ] {
            assert_eq!(
                check_addr(ip(a), true),
                Err(UrlError::Blocked),
                "{a} mit Allowlist"
            );
            assert_eq!(
                check_addr(ip(a), false),
                Err(UrlError::Blocked),
                "{a} ohne Allowlist"
            );
        }
    }

    #[test]
    fn embedded_private_ipv4_is_not_global() {
        // IPv4-mapped/NAT64/6to4 mit privater Adresse zählt als intern (nicht öffentlich), aber nicht als immer gesperrt.
        for a in [
            "::ffff:10.0.0.1",
            "::ffff:192.168.0.1",
            "64:ff9b::a00:1",
            "2002:c0a8:1::1",
        ] {
            assert!(!is_global(ip(a)), "{a}");
            assert_eq!(check_addr(ip(a), false), Err(UrlError::Blocked), "{a}");
            assert!(check_addr(ip(a), true).is_ok(), "{a}");
        }
        assert!(is_global(ip("::ffff:8.8.8.8")));
    }

    #[test]
    fn allowlist_is_exact() {
        let allowed = vec!["gotify.lan".to_owned(), "10.0.0.5".to_owned()];
        assert!(host_allowed("gotify.lan", &allowed));
        assert!(host_allowed("GOTIFY.LAN", &allowed));
        assert!(host_allowed("10.0.0.5", &allowed));
        // keine Subdomains, keine Präfixe, keine Netze
        assert!(!host_allowed("evil.gotify.lan", &allowed));
        assert!(!host_allowed("gotify.lan.evil.org", &allowed));
        assert!(!host_allowed("10.0.0.6", &allowed));
        assert!(!host_allowed("10.0.0.50", &allowed));
    }

    #[tokio::test]
    async fn resolve_checks_every_address() {
        // IP-Literale: kein DNS nötig.
        let u = |s: &str| parse_url(s, false).unwrap();
        assert!(resolve(u("https://8.8.8.8"), &[]).await.is_ok());
        assert_eq!(
            resolve(u("http://127.0.0.1:8080"), &[]).await.unwrap_err(),
            UrlError::Blocked
        );
        assert_eq!(
            resolve(u("http://127.0.0.1:8080"), &["127.0.0.1".into()])
                .await
                .unwrap_err(),
            UrlError::Blocked
        );
        assert_eq!(
            resolve(u("http://[::1]/"), &["::1".into()])
                .await
                .unwrap_err(),
            UrlError::Blocked
        );
        assert_eq!(
            resolve(
                u("http://169.254.169.254/latest/meta-data"),
                &["169.254.169.254".into()]
            )
            .await
            .unwrap_err(),
            UrlError::Blocked
        );
        assert_eq!(
            resolve(u("http://10.1.2.3"), &[]).await.unwrap_err(),
            UrlError::Blocked
        );
        assert!(resolve(u("http://10.1.2.3"), &["10.1.2.3".into()])
            .await
            .is_ok());
        // "localhost" löst auf Loopback auf: gesperrt, auch wenn eingetragen.
        assert_eq!(
            resolve(u("http://localhost:9/"), &["localhost".into()])
                .await
                .unwrap_err(),
            UrlError::Blocked
        );
    }
}
