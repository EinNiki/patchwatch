//! Fund 6: Ein Umgebungs-Proxy darf die SSRF-Prüfung (gepinnte, geprüfte IP) nicht umgehen.
//!
//! Eigene Testdatei mit genau einem Test: Umgebungsvariablen gelten prozessweit, andere Tests dürfen nicht stören.

use patchwatch_server::notify::ssrf::{self, Target};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Einfacher HTTP-Server: antwortet 200 mit `body` und zählt die Verbindungen.
async fn serve(body: &'static str) -> (SocketAddr, Arc<AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                return;
            };
            h.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = s.write_all(resp.as_bytes()).await;
            });
        }
    });
    (addr, hits)
}

#[tokio::test]
async fn fund6_proxy_environment_does_not_bypass_the_pinned_address() {
    let (target_addr, target_hits) = serve("direkt").await;
    let (proxy_addr, proxy_hits) = serve("proxy").await;
    // Prozessweit; dies ist der einzige Test dieser Datei.
    for k in [
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        std::env::set_var(k, format!("http://{proxy_addr}"));
    }
    std::env::remove_var("NO_PROXY");
    std::env::remove_var("no_proxy");

    // Name, der nur über die gepinnte Adresse erreichbar ist (existiert nicht im DNS).
    let url: reqwest::Url = format!("http://pinned.invalid:{}/x", target_addr.port())
        .parse()
        .unwrap();
    let target = Target {
        url: url.clone(),
        host: "pinned.invalid".into(),
        addrs: vec![target_addr],
    };

    // Gegenprobe: ein Client MIT Umgebungs-Proxy landet beim Proxy (zeigt, dass der Test den Fehler erfassen würde).
    let proxied = reqwest::Client::builder().build().unwrap();
    let r = proxied
        .get(url.clone())
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(
        r, "proxy",
        "Gegenprobe: ohne no_proxy geht die Anfrage an den Proxy"
    );
    let (t0, p0) = (
        target_hits.load(Ordering::SeqCst),
        proxy_hits.load(Ordering::SeqCst),
    );
    assert_eq!((t0, p0), (0, 1));

    // Gepinnter Client: direkt zur geprüften Adresse, der Proxy sieht nichts.
    let c = ssrf::pinned_client(&target).unwrap();
    let r = c
        .get(url.clone())
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(r, "direkt");
    assert_eq!(target_hits.load(Ordering::SeqCst), 1);
    assert_eq!(
        proxy_hits.load(Ordering::SeqCst),
        1,
        "der Proxy darf keine weitere Anfrage sehen"
    );

    // Vertrauenswürdiger Pfad (Allowlist): ebenfalls kein Proxy. Ziel als IP-Literal, damit keine Auflösung nötig ist.
    let direct: reqwest::Url = format!("http://{target_addr}/y").parse().unwrap();
    let c = ssrf::trusted_client().unwrap();
    let r = c.get(direct).send().await.unwrap().text().await.unwrap();
    assert_eq!(r, "direkt");
    assert_eq!(target_hits.load(Ordering::SeqCst), 2);
    assert_eq!(proxy_hits.load(Ordering::SeqCst), 1);
}
