//! Minimaler, nur lesender Docker-Client: HTTP/1.1 über einen Unix-Socket oder einen Loopback-Port (Socket-Proxy).
//!
//! Sicherheitsrahmen: Es gibt genau eine Methode (`GET`) und eine Positivliste von Pfaden (`allowed_path`). Alles andere,
//! etwa `/containers/<id>/exec`, `/containers/<id>/json` (enthält Umgebungsvariablen) oder `POST`, ist gar nicht erst
//! ausdrückbar. Antworten sind auf `MAX_RESPONSE` Byte begrenzt, jede Verbindung hat Zeitgrenzen.
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Größte akzeptierte Antwort (Kopf und Rumpf, entpackt).
pub const MAX_RESPONSE: usize = 8 * 1024 * 1024;
pub const DEFAULT_ENDPOINT: &str = "unix:///var/run/docker.sock";

#[derive(Debug, PartialEq, Eq)]
pub enum DockerError {
    SocketMissing,
    NoPermission,
    Timeout,
    BadResponse,
    /// Der Pfad steht nicht in der Positivliste (Programmierfehler, nie Eingabe von außen).
    Refused,
}

impl DockerError {
    /// Fester Grund für den Bericht (der Server kennt genau diese Werte).
    pub fn reason(&self) -> &'static str {
        match self {
            Self::SocketMissing => "socket_missing",
            Self::NoPermission => "no_permission",
            Self::Timeout => "timeout",
            Self::BadResponse | Self::Refused => "bad_response",
        }
    }
}

/// Lesender Zugriff auf Docker; als Trait, damit Tests ohne Docker auskommen.
pub trait DockerApi {
    /// Rumpf einer erfolgreichen (HTTP 200) Antwort.
    fn get(&self, path: &str) -> Result<Vec<u8>, DockerError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    Unix(PathBuf),
    Tcp(SocketAddr),
}

impl Endpoint {
    /// `unix:///absoluter/pfad` oder `http://127.0.0.1:<port>` (auch `localhost`, `[::1]`). Andere Ziele sind verboten:
    /// der Agent spricht nie mit einem Docker-Dienst im Netz.
    pub fn parse(s: &str) -> Result<Self, String> {
        if let Some(p) = s.strip_prefix("unix://") {
            let path = PathBuf::from(p);
            let plain = path.is_absolute()
                && path
                    .components()
                    .all(|c| !matches!(c, std::path::Component::ParentDir));
            return if plain && p.len() > 1 {
                Ok(Self::Unix(path))
            } else {
                Err("docker_endpoint: unix:// braucht einen absoluten Pfad ohne ..".into())
            };
        }
        let rest = s.strip_prefix("http://").ok_or_else(|| {
            "docker_endpoint muss unix:///pfad oder http://127.0.0.1:PORT sein".to_owned()
        })?;
        let (host, port) = rest
            .trim_end_matches('/')
            .rsplit_once(':')
            .ok_or("docker_endpoint: Port fehlt")?;
        let port: u16 = port
            .parse()
            .ok()
            .filter(|p| *p > 0)
            .ok_or("docker_endpoint: ungültiger Port")?;
        let ip = match host {
            "localhost" | "127.0.0.1" => IpAddr::V4(Ipv4Addr::LOCALHOST),
            "[::1]" => IpAddr::V6(Ipv6Addr::LOCALHOST),
            _ => {
                return Err(
                    "docker_endpoint: nur Loopback (127.0.0.1, [::1], localhost) ist erlaubt"
                        .into(),
                )
            }
        };
        Ok(Self::Tcp(SocketAddr::new(ip, port)))
    }
}

/// Positivliste: `/containers/json?all=true` und `/images/<id>/json`. Keine weiteren Zeichen, keine Abfrageparameter
/// außer dem einen festen.
pub fn allowed_path(path: &str) -> bool {
    if path == "/containers/json?all=true" {
        return true;
    }
    let Some(id) = path
        .strip_prefix("/images/")
        .and_then(|p| p.strip_suffix("/json"))
    else {
        return false;
    };
    let hex = id.strip_prefix("sha256:").unwrap_or(id);
    (12..=64).contains(&hex.len()) && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub struct HttpDocker {
    endpoint: Endpoint,
    timeout: Duration,
}

impl HttpDocker {
    pub fn new(endpoint: Endpoint) -> Self {
        Self {
            endpoint,
            timeout: Duration::from_secs(5),
        }
    }

    #[cfg(test)]
    fn with_timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }

    fn connect_error(e: &std::io::Error) -> DockerError {
        use std::io::ErrorKind::*;
        match e.kind() {
            NotFound | ConnectionRefused => DockerError::SocketMissing,
            PermissionDenied => DockerError::NoPermission,
            TimedOut | WouldBlock => DockerError::Timeout,
            _ => DockerError::BadResponse,
        }
    }

    fn exchange(&self, path: &str) -> Result<Vec<u8>, DockerError> {
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: docker\r\nUser-Agent: patchwatch-agent\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
        );
        let deadline = Instant::now() + self.timeout * 2;
        match &self.endpoint {
            Endpoint::Unix(p) => {
                let mut s = UnixStream::connect(p).map_err(|e| Self::connect_error(&e))?;
                s.set_read_timeout(Some(self.timeout)).ok();
                s.set_write_timeout(Some(self.timeout)).ok();
                s.write_all(request.as_bytes())
                    .map_err(|e| Self::connect_error(&e))?;
                read_limited(&mut s, deadline)
            }
            Endpoint::Tcp(a) => {
                let mut s = TcpStream::connect_timeout(a, self.timeout)
                    .map_err(|e| Self::connect_error(&e))?;
                s.set_read_timeout(Some(self.timeout)).ok();
                s.set_write_timeout(Some(self.timeout)).ok();
                s.write_all(request.as_bytes())
                    .map_err(|e| Self::connect_error(&e))?;
                read_limited(&mut s, deadline)
            }
        }
    }
}

impl DockerApi for HttpDocker {
    fn get(&self, path: &str) -> Result<Vec<u8>, DockerError> {
        if !allowed_path(path) {
            return Err(DockerError::Refused);
        }
        parse_response(&self.exchange(path)?)
    }
}

/// Liest bis zum Ende der Verbindung (`Connection: close`), höchstens `MAX_RESPONSE` Byte und bis zur Frist.
fn read_limited(r: &mut dyn Read, deadline: Instant) -> Result<Vec<u8>, DockerError> {
    let mut out = Vec::new();
    let mut buf = [0u8; 16 * 1024];
    loop {
        if Instant::now() > deadline {
            return Err(DockerError::Timeout);
        }
        match r.read(&mut buf) {
            Ok(0) => return Ok(out),
            Ok(n) => {
                if out.len() + n > MAX_RESPONSE {
                    return Err(DockerError::BadResponse);
                }
                out.extend_from_slice(&buf[..n]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(HttpDocker::connect_error(&e)),
        }
    }
}

/// Statuszeile, Kopf und Rumpf (Content-Length oder chunked). Nur HTTP 200 liefert einen Rumpf.
fn parse_response(raw: &[u8]) -> Result<Vec<u8>, DockerError> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or(DockerError::BadResponse)?;
    let head = std::str::from_utf8(&raw[..split]).map_err(|_| DockerError::BadResponse)?;
    let body = &raw[split + 4..];
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap_or("");
    let code = status
        .strip_prefix("HTTP/1.")
        .and_then(|s| s.get(2..5))
        .ok_or(DockerError::BadResponse)?;
    if code != "200" {
        return Err(DockerError::BadResponse);
    }
    let mut chunked = false;
    let mut length: Option<usize> = None;
    for l in lines {
        let Some((k, v)) = l.split_once(':') else {
            return Err(DockerError::BadResponse);
        };
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
        match k.as_str() {
            "transfer-encoding" if v.eq_ignore_ascii_case("chunked") => chunked = true,
            "content-length" => length = Some(v.parse().map_err(|_| DockerError::BadResponse)?),
            _ => {}
        }
    }
    if chunked {
        return decode_chunked(body);
    }
    match length {
        Some(n) if body.len() >= n => Ok(body[..n].to_vec()),
        Some(_) => Err(DockerError::BadResponse),
        None => Ok(body.to_vec()),
    }
}

fn decode_chunked(mut b: &[u8]) -> Result<Vec<u8>, DockerError> {
    let mut out = Vec::new();
    loop {
        let eol = b
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or(DockerError::BadResponse)?;
        let size_text = std::str::from_utf8(&b[..eol]).map_err(|_| DockerError::BadResponse)?;
        // Chunk-Erweiterungen (nach `;`) werden ignoriert.
        let size = usize::from_str_radix(size_text.split(';').next().unwrap_or("").trim(), 16)
            .map_err(|_| DockerError::BadResponse)?;
        b = &b[eol + 2..];
        if size == 0 {
            return Ok(out);
        }
        if b.len() < size + 2 || &b[size..size + 2] != b"\r\n" || out.len() + size > MAX_RESPONSE {
            return Err(DockerError::BadResponse);
        }
        out.extend_from_slice(&b[..size]);
        b = &b[size + 2..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    const ID: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn only_the_two_read_paths_are_allowed() {
        assert!(allowed_path("/containers/json?all=true"));
        assert!(allowed_path(&format!("/images/{ID}/json")));
        assert!(allowed_path("/images/0123456789ab/json"));
        for bad in [
            "/containers/json",
            "/containers/json?all=true&size=1",
            "/containers/json?all=false",
            "/containers/abc/json",
            "/containers/abc/exec",
            "/containers/abc/logs",
            "/images/create?fromImage=x",
            "/images/json",
            "/images/abc/json",
            "/images/../containers/json/json",
            "/images/0123456789ab/json?x=1",
            "/images/0123456789AB/json",
            "/images/0123456789ab/history",
            "/v1.45/containers/json?all=true",
            "/_ping",
            "/info",
            "/volumes",
            "",
        ] {
            assert!(!allowed_path(bad), "{bad} darf nicht erlaubt sein");
        }
    }

    #[test]
    fn endpoints_are_unix_paths_or_loopback_only() {
        assert_eq!(
            Endpoint::parse(DEFAULT_ENDPOINT).unwrap(),
            Endpoint::Unix("/var/run/docker.sock".into())
        );
        assert_eq!(
            Endpoint::parse("http://127.0.0.1:2375").unwrap(),
            Endpoint::Tcp("127.0.0.1:2375".parse().unwrap())
        );
        assert_eq!(
            Endpoint::parse("http://localhost:2375").unwrap(),
            Endpoint::Tcp("127.0.0.1:2375".parse().unwrap())
        );
        assert_eq!(
            Endpoint::parse("http://[::1]:2375").unwrap(),
            Endpoint::Tcp("[::1]:2375".parse().unwrap())
        );
        for bad in [
            "http://192.168.1.5:2375",
            "http://docker.example.org:2375",
            "https://127.0.0.1:2375",
            "http://127.0.0.1",
            "http://127.0.0.1:0",
            "http://127.0.0.1.evil.org:2375",
            "unix://relativ/docker.sock",
            "unix:///var/run/../docker.sock",
            "unix:///",
            "tcp://127.0.0.1:2375",
            "",
        ] {
            assert!(Endpoint::parse(bad).is_err(), "{bad}");
        }
    }

    fn temp_sock(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("pw-agent-{}-dk-{name}", std::process::id()));
        let _ = std::fs::remove_file(&d);
        d
    }

    /// Einmaliger Server: liest die Anfrage, schickt `reply` und schließt. Liefert die empfangene Anfrage zurück.
    fn serve_once(path: &PathBuf, reply: Vec<u8>) -> std::thread::JoinHandle<String> {
        let l = UnixListener::bind(path).unwrap();
        std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut req = Vec::new();
            let mut b = [0u8; 1024];
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = s.read(&mut b).unwrap();
                if n == 0 {
                    break;
                }
                req.extend_from_slice(&b[..n]);
            }
            s.write_all(&reply).ok();
            String::from_utf8_lossy(&req).into_owned()
        })
    }

    #[test]
    fn reads_content_length_and_sends_only_a_get() {
        let p = temp_sock("cl");
        let h = serve_once(&p, b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 7\r\n\r\n[1,2,3]extra".to_vec());
        let c = HttpDocker::new(Endpoint::Unix(p.clone()));
        assert_eq!(c.get("/containers/json?all=true").unwrap(), b"[1,2,3]");
        let req = h.join().unwrap();
        assert!(
            req.starts_with("GET /containers/json?all=true HTTP/1.1\r\n"),
            "{req}"
        );
        assert!(req.contains("Connection: close"));
        assert_eq!(
            req.matches("\r\n").count(),
            6,
            "keine Zusatzköpfe, kein Rumpf: {req:?}"
        );
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn reads_chunked_bodies() {
        let p = temp_sock("ch");
        let h = serve_once(&p, b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\n[1,\r\n4;ext=1\r\n2,3]\r\n0\r\n\r\n".to_vec());
        let c = HttpDocker::new(Endpoint::Unix(p.clone()));
        assert_eq!(c.get("/containers/json?all=true").unwrap(), b"[1,2,3]");
        h.join().unwrap();
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn rejects_errors_truncation_and_garbage() {
        for (name, reply) in [
            (
                "404",
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
            ),
            (
                "short",
                b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n[1]".to_vec(),
            ),
            ("garbage", b"\x00\x01nonsense".to_vec()),
            (
                "badchunk",
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZZ\r\nabc\r\n".to_vec(),
            ),
            (
                "nochunkend",
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nabc".to_vec(),
            ),
        ] {
            let p = temp_sock(name);
            let h = serve_once(&p, reply);
            let c = HttpDocker::new(Endpoint::Unix(p.clone()));
            assert_eq!(
                c.get("/containers/json?all=true"),
                Err(DockerError::BadResponse),
                "{name}"
            );
            h.join().unwrap();
            let _ = std::fs::remove_file(p);
        }
    }

    #[test]
    fn oversized_responses_are_refused() {
        let p = temp_sock("big");
        let mut reply = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
        reply.extend(std::iter::repeat_n(b'x', MAX_RESPONSE + 1));
        let h = serve_once(&p, reply);
        let c = HttpDocker::new(Endpoint::Unix(p.clone()));
        assert_eq!(
            c.get("/containers/json?all=true"),
            Err(DockerError::BadResponse)
        );
        h.join().unwrap();
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn missing_socket_and_silent_server_have_their_own_reasons() {
        let c = HttpDocker::new(Endpoint::Unix("/nonexistent/docker.sock".into()));
        assert_eq!(
            c.get("/containers/json?all=true"),
            Err(DockerError::SocketMissing)
        );
        assert_eq!(DockerError::SocketMissing.reason(), "socket_missing");

        // Ein Server, der annimmt und nie antwortet.
        let p = temp_sock("silent");
        let l = UnixListener::bind(&p).unwrap();
        let t = std::thread::spawn(move || {
            let (s, _) = l.accept().unwrap();
            std::thread::sleep(Duration::from_millis(800));
            drop(s);
        });
        let c = HttpDocker::new(Endpoint::Unix(p.clone())).with_timeout(Duration::from_millis(150));
        assert_eq!(
            c.get("/containers/json?all=true"),
            Err(DockerError::Timeout)
        );
        t.join().unwrap();
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn a_path_outside_the_list_never_touches_the_socket() {
        // Der Socket existiert nicht: käme der Pfad durch, wäre der Fehler SocketMissing statt Refused.
        let c = HttpDocker::new(Endpoint::Unix("/nonexistent/docker.sock".into()));
        assert_eq!(c.get("/containers/abc/exec"), Err(DockerError::Refused));
    }

    #[test]
    fn loopback_tcp_works_like_the_socket() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let t = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut b = [0u8; 512];
            let _ = s.read(&mut b);
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n[]")
                .unwrap();
        });
        let c = HttpDocker::new(Endpoint::parse(&format!("http://127.0.0.1:{port}")).unwrap());
        assert_eq!(c.get("/containers/json?all=true").unwrap(), b"[]");
        t.join().unwrap();
    }
}
