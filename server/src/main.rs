use anyhow::{bail, Context, Result};
use patchwatch_server::{admin, config::Config, worker, AppState, MIGRATOR};
use sqlx::postgres::PgPoolOptions;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::time::Duration;

const USAGE: &str =
    "Verwendung: patchwatch-server [serve | create-admin <benutzer> | migrate | healthcheck]\n\
  create-admin liest das Passwort aus PATCHWATCH_ADMIN_PASSWORD oder von stdin.";

/// Minimaler HTTP-Check für Docker-HEALTHCHECK (kein curl im Image nötig).
fn healthcheck(listen: &str) -> Result<()> {
    let port = listen.rsplit(':').next().context("listen ohne Port")?;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse()?;
    let mut s = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(3))?;
    s.set_read_timeout(Some(Duration::from_secs(3)))?;
    s.write_all(b"GET /readyz HTTP/1.0\r\nHost: localhost\r\n\r\n")?;
    let mut buf = String::new();
    s.read_to_string(&mut buf)?;
    if buf.starts_with("HTTP/1.0 200") || buf.starts_with("HTTP/1.1 200") {
        Ok(())
    } else {
        bail!("nicht bereit")
    }
}

async fn connect(cfg: &Config) -> Result<sqlx::PgPool> {
    PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(Duration::from_secs(5))
        .connect(cfg.database_url()?)
        .await
        .context("Datenbankverbindung fehlgeschlagen")
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! { () = ctrl_c => {}, () = term => {} }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let cfg = Config::load()?;
    match args.first().map(String::as_str).unwrap_or("serve") {
        "healthcheck" => healthcheck(&cfg.listen),
        "migrate" => {
            MIGRATOR.run(&connect(&cfg).await?).await?;
            println!("Migrationen angewendet");
            Ok(())
        }
        "create-admin" => {
            let user = args.get(1).context("Benutzername fehlt")?;
            let pw = match std::env::var("PATCHWATCH_ADMIN_PASSWORD") {
                Ok(p) => p,
                Err(_) => {
                    let mut line = String::new();
                    std::io::stdin().read_line(&mut line)?;
                    line.trim_end_matches(['\r', '\n']).to_owned()
                }
            };
            let pool = connect(&cfg).await?;
            MIGRATOR.run(&pool).await?;
            admin::upsert_admin(&pool, user, &pw).await?;
            println!("Admin {user} angelegt/aktualisiert");
            Ok(())
        }
        "serve" => {
            let pool = connect(&cfg).await?;
            MIGRATOR.run(&pool).await?;
            // Erster Start: Admin nur anlegen, solange noch keiner existiert -- nie mit einem festen, bekannten Wert.
            // Explizit per PATCHWATCH_ADMIN_PASSWORD (mind. 12 Zeichen); sonst Zufallspasswort, das genau einmal
            // auf stderr erscheint. (PATCHWATCH_INITIAL_ADMIN_PASSWORD gilt weiter als alter Name.)
            let env_pw = std::env::var("PATCHWATCH_ADMIN_PASSWORD")
                .ok()
                .filter(|p| !p.is_empty())
                .or_else(|| std::env::var("PATCHWATCH_INITIAL_ADMIN_PASSWORD").ok());
            match admin::bootstrap_admin(&pool, env_pw.as_deref()).await? {
                admin::Bootstrap::Existing => {}
                admin::Bootstrap::FromEnv => {
                    tracing::info!("Admin 'admin' mit PATCHWATCH_ADMIN_PASSWORD angelegt");
                }
                admin::Bootstrap::Random(pw) => {
                    // Absichtlich eprintln statt tracing: genau einmal, nicht in strukturierte Logs, nie gespeichert.
                    eprintln!(
                        "\n================================================================\n\
                         patchwatch: Erster Start, Benutzer 'admin' wurde angelegt.\n\
                         Einmaliges Start-Passwort: {pw}\n\
                         Es wird nicht gespeichert und nicht noch einmal angezeigt. Beim ersten\n\
                         Login muss es sofort geändert werden (mindestens 12 Zeichen).\n\
                         ================================================================\n"
                    );
                    tracing::warn!("Admin 'admin' mit Zufallspasswort angelegt (auf stderr ausgegeben), Passwortwechsel beim ersten Login erforderlich");
                }
            }
            // Bestehende Installationen: Konten, die noch das frühere Standardpasswort haben, müssen es ändern.
            let weak = admin::flag_default_passwords(&pool).await?;
            if !weak.is_empty() {
                tracing::warn!(
                    users = ?weak,
                    "WARNUNG: Diese Admin-Konten nutzen noch das frühere, öffentlich bekannte Standardpasswort. Sie können sich nur noch anmelden, um das Passwort zu ändern."
                );
            }
            let listen = cfg.listen.clone();
            let state = AppState::new(pool, cfg)?;
            // Statuswerte einmal neu berechnen (Bewertungsregeln können sich zwischen Versionen ändern).
            let re = state.clone();
            tokio::spawn(async move {
                if let Err(e) = patchwatch_server::cve::reeval::reevaluate_all(&re).await {
                    tracing::warn!(error = %e, "Neubewertung beim Start fehlgeschlagen");
                }
            });
            tokio::spawn(patchwatch_server::live::run(state.clone()));
            tokio::spawn(worker::scheduler(state.clone()));
            tokio::spawn(patchwatch_server::cve::refresh::run(state.clone()));
            let w = state.clone();
            tokio::spawn(async move {
                if let Err(e) = worker::run(w).await {
                    tracing::error!(error = %e, "Worker beendet");
                }
            });
            let listener = tokio::net::TcpListener::bind(&listen)
                .await
                .with_context(|| format!("bind {listen}"))?;
            tracing::info!(%listen, "patchwatch-server gestartet");
            axum::serve(
                listener,
                patchwatch_server::router(state)
                    .into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(shutdown_signal())
            .await?;
            Ok(())
        }
        _ => bail!("{USAGE}"),
    }
}
