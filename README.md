# patchwatch

[![CI](https://github.com/EinNiki/patchwatch/actions/workflows/ci.yml/badge.svg)](https://github.com/EinNiki/patchwatch/actions/workflows/ci.yml)
[![Release](https://github.com/EinNiki/patchwatch/actions/workflows/release.yml/badge.svg)](https://github.com/EinNiki/patchwatch/actions/workflows/release.yml)

Leichtgewichtiges Monitoring für Kernel- und Patch-Stand mehrerer Linux-Server
(Ubuntu, Debian, Proxmox) mit CVE-Abgleich und Web-UI.

Status: im Aufbau. Aufbau: `agent/`, `server/`, `web/`, gemeinsame Crates in `crates/`.
Einrichtung des GitHub-Repos: [docs/github-setup.md](docs/github-setup.md).

## Agent

Statisches musl-Binary (~2 MB), läuft einmal pro Aufruf (systemd-Timer, täglich 12:00
mit `RandomizedDelaySec=30min`), ohne Root-Rechte und ohne offenen Port. Sendet per
HTTPS POST an `/api/v1/report` mit Bearer-Token.

Installation (als root, Token kommt aus dem Server, siehe Betrieb):

```sh
PATCHWATCH_TOKEN=… sh install.sh --server-url https://patchwatch.example.org
```

`install.sh` lädt das Binary aus dem GitHub Release und prüft die SHA256-Summe vor der
Installation. Der Token liegt in `/etc/patchwatch/token` (`root:root 0600`) und wird per
systemd-`LoadCredential` an den Dienst `patchwatch` (kein `DynamicUser`) gereicht.
Konfiguration: `/etc/patchwatch/agent.toml`, Beispiel in `agent/dist/agent.toml.example`.

Exit-Codes: `1` Konfiguration, `2` Erfassung, `3` Server nicht erreichbar, `4` Server lehnt ab.
Fehlermeldungen (ohne Token) landen im journald: `journalctl -u patchwatch-agent`.
`patchwatch-agent --dry-run` gibt den Report als JSON aus, ohne zu senden.

## Server

Rust (axum, tokio, sqlx) mit PostgreSQL. Migrationen laufen beim Start (`server/migrations`).

```sh
cp .env.example .env            # POSTGRES_PASSWORD setzen (openssl rand -hex 24)
docker compose up -d
docker compose exec -T -e PATCHWATCH_ADMIN_PASSWORD='…mind. 12 Zeichen…' server patchwatch-server create-admin admin
```

Host und Agent-Token anlegen (Web-UI folgt; bis dahin per API, Token wird nur einmal angezeigt
und serverseitig nur als SHA-256-Hash gespeichert):

```sh
curl -c jar -H 'content-type: application/json' -d '{"username":"admin","password":"…"}' https://patchwatch.example.org/api/v1/auth/login
curl -b jar -H "x-csrf-token: <csrf_token aus der Antwort>" -H 'content-type: application/json' \
     -d '{"name":"web1"}' https://patchwatch.example.org/api/v1/hosts
```

Konfiguration per Datei (`/etc/patchwatch/server.toml`, Pfad über `PATCHWATCH_CONFIG`) oder
Umgebungsvariablen `PATCHWATCH_*` (siehe `docker-compose.yml`). Wichtige Werte:
`stale_after_hours` (26), `report_retention_days` (180), `timezone`, `daily_summary_time`,
`ntfy.url`/`ntfy.topic`/`ntfy.token`, `trust_proxy`, `cookie_secure`. Secrets erscheinen nicht in Logs.

Verhalten: Ein Host gilt als **stale**, wenn er sich länger als 26 h nicht gemeldet hat. Jeder
Statuswechsel erzeugt ein Event und (bei konfiguriertem ntfy) sofort eine Benachrichtigung; zusätzlich
gibt es eine Tageszusammenfassung zur konfigurierten Uhrzeit. Die Report-Historie wird nach
`report_retention_days` per täglichem Cleanup-Job gelöscht.

### Warum kein Redis?

Es gibt keinen nachweisbaren Bedarf: Die Job-Queue (Benachrichtigungen mit Retry/Backoff,
Cleanup, Tageszusammenfassung) nutzt `FOR UPDATE SKIP LOCKED`, Events und Wakeups laufen über
`LISTEN/NOTIFY`. Das Datenaufkommen (ein Report je Host und Tag) braucht keinen Cache. Redis wird
daher weder benötigt noch eingesetzt; das spart einen Dienst im Betrieb.

### Sicherheit

Admin-Login mit argon2id, Session-Cookie (`HttpOnly`, `Secure`, `SameSite=Strict`, nur als Hash
gespeichert), CSRF-Token für alle verändernden Aufrufe, Rate-Limits (Login je IP und Benutzer,
Reports, allgemeine API), strikte Eingabevalidierung, Body-Limit 4 MB. Server nur über
VPN/WireGuard oder hinter einem TLS-Reverse-Proxy erreichbar machen; `trust_proxy=true` nur
setzen, wenn ein vertrauenswürdiger Proxy davorsteht und den echten Client in `X-Forwarded-For` anhängt.
