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

## CVE-Abgleich

Ein Hintergrund-Scheduler im Server ruft alle 60 Minuten (konfigurierbar, mit bis zu 10 % Jitter) die Feeds ab.
Jede Quelle ist ein Adapter hinter dem Trait `CveSource` (`server/src/cve/`); weitere Quellen wie Red Hat
oder Alpine kommen als eigener Adapter dazu. Zunächst nur Kernel-Pakete (`linux`, `linux-hwe-6.8`, `linux-aws` …),
das Datenmodell (`cve_source_status` je CVE, Quelle, Release, Paket) ist für beliebige Pakete ausgelegt.

| Quelle | Abruf | Besonderheit (an echten Antworten geprüft) |
|---|---|---|
| Ubuntu `cves.json` | inkrementell | Die API hat **keinen** „updated since“-Filter. Es wird absteigend nach `updated` paginiert (20 CVEs, ca. 3,7 MB je Seite) und am gespeicherten Cursor gestoppt. Erstabruf: die neuesten 5 Seiten; Watchlist-CVEs außerhalb davon werden einzeln nachgeladen. |
| Debian Security Tracker | bedingt | Es gibt **keinen ETag**, aber `Last-Modified`: `If-Modified-Since` ergibt bei Unverändertem 304 und es passiert nichts. 87 MB entpackt, daher streamendes Parsen (nur Kernel-Pakete) und hartes Größenlimit. |
| OSV.dev (optional, `PATCHWATCH_CVE_SOURCES=ubuntu,debian,osv`) | je Host-Kernelversion | Ergänzend; Distributions-Tracker haben Vorrang. Antworten enthalten fremde Ökosysteme (werden gefiltert) und sind paginiert. |

**Bewertung** (`fixed`, `vulnerable`, `fix pending`, `not affected`, `UNKNOWN`) erfolgt pro Host und CVE für den
**laufenden** Kernel, mit dpkg-Versionsvergleich (Crate `debversion`). Zusätzlich gibt es **„gefixt installiert,
Neustart nötig“**: Der Fix steckt in einem installierten, aber noch nicht gebooteten Kernel. Jede Bewertung
speichert eine Begründung und die zugrunde liegenden Quelleneinträge (Klick in der Matrix).

**Änderungserkennung:** Je (CVE, Quelle, Release, Paket) wird der normalisierte Status gespeichert. Eine neue CVE
oder ein geänderter Status (z. B. `vulnerable` → `fixed in 6.8.0-35.35`) erzeugt sofort ein Event, betroffene Hosts
werden neu bewertet, und ein Wechsel des Host-Status löst die Benachrichtigung aus. Der erste Import einer Quelle
erzeugt bewusst keine Event-Flut. Watchlist-CVEs werden im UI hervorgehoben und bei Änderungen gemeldet.

**Fehlerrobustheit:** Ist ein Feed nicht erreichbar oder hat sich sein Format geändert, bleibt der alte Stand
erhalten, der Fehler wird gespeichert und unter `GET /api/v1/feeds` als „veraltet seit …“ ausgewiesen (auch wenn
der Scheduler hängt). Nie wird eine Quelle stillschweigend als gesund gewertet. Abrufe haben Timeouts,
Größenlimits und Retry mit Backoff; nach 3 Fehlschlägen in Folge gibt es genau eine Benachrichtigung.

### Grenzen der CVE-Bewertung

- **Proxmox-Kernel (`-pve`) haben keine belastbare CVE-Quelle.** Sie werden immer als **UNKNOWN** bewertet („manuell
  prüfen“, Link zu den [Proxmox Security Advisories](https://forum.proxmox.com/forums/security-advisories.26/)),
  nie als „grün“, und lösen **keinen** ntfy-Alarm aus. Im UI lässt sich „geprüft am …“ setzen; die Markierung
  verfällt, sobald sich der laufende Kernel ändert.
- UNKNOWN gilt auch bei fehlender Datenlage (kein Eintrag im Tracker, Quellpaket nicht zuordenbar, unbekannter
  Status, ungültige Version), nie „behoben“.
- Ubuntu-Status `ignored` und `deferred` zählen als verwundbar (der Hersteller behebt nicht). Ubuntu `DNE` wird ignoriert.
- Es werden nur CVEs bewertet, die in den geladenen Feeddaten vorkommen: bei Ubuntu die zuletzt aktualisierten und
  die Watchlist, bei Debian alle Kernel-CVEs. Gespeichert werden nur Ergebnisse mit Handlungsbezug (verwundbar,
  Fix angekündigt, Neustart nötig, unbekannt) und alle Watchlist-Einträge; die Matrix berechnet weitere Zellen live.
- Hosts, die einen Kernel aus einem Repository ohne passende Tracker-Daten nutzen (z. B. Backports), werden UNKNOWN.

## Web-UI

Next.js (App Router, TypeScript, Tailwind) in `web/`. Die UI hat **kein eigenes Backend**: Sie spricht nur mit der
Rust-API unter `/api/v1` (Sitzungs-Cookie + CSRF-Token). Seiten: Host-Übersicht (sortier- und filterbar, URL-Zustand),
Host-Detail (Kernel, Neustart, Updates, CVE-Bewertung mit Begründung, Verlauf), CVE-Liste mit Watchlist und
Feed-Zustand je Quelle („veraltet seit …“), Einstellungen (Hosts, Agent-Tokens einmalig anzeigen, erneuern, löschen).
Die Matrix-Seite folgt; die Navigation hat den Platz („Matrix – bald“) bereits.

Design und Barrierefreiheit sind in [`web/DESIGN.md`](web/DESIGN.md) festgelegt (Palette mit gemessenen Kontrasten,
Schriften, Statusdarstellung: immer Icon + Text + Farbe, nie „grün“ bei fehlender Datenlage). Hell/Dunkel folgt dem System.
Mit axe-core gegen Hell, Dunkel und Mobil geprüft: keine Verstöße.

### Betrieb mit TLS

`docker compose up -d` startet Postgres, Server und Web (nur auf `127.0.0.1`). Für TLS gibt es einen optionalen
Caddy-Proxy (`/api` → Server, alles andere → Web): `PATCHWATCH_DOMAIN` in `.env` setzen und
`docker compose --profile proxy up -d`. Hinter einem eigenen Proxy genügt: `/api/*` an `127.0.0.1:8080`, der Rest
an `127.0.0.1:3000`, und dem Server `PATCHWATCH_TRUST_PROXY=true` geben (siehe `deploy/Caddyfile`).

### Entwicklung

```sh
docker run -d --name pw-pg -e POSTGRES_USER=patchwatch -e POSTGRES_PASSWORD=dev -e POSTGRES_DB=patchwatch -p 127.0.0.1:5432:5432 postgres:17-alpine
export PATCHWATCH_DATABASE_URL=postgres://patchwatch:dev@127.0.0.1:5432/patchwatch PATCHWATCH_COOKIE_SECURE=false
cargo run -p patchwatch-server -- create-admin admin      # Passwort per stdin oder PATCHWATCH_ADMIN_PASSWORD
cargo run -p patchwatch-server                             # API auf :8080
python3 scripts/dev-seed.py http://127.0.0.1:8080 admin    # Beispielhosts und -reports
cd web && npm ci && npm run dev                            # UI auf :3000, /api wird an :8080 weitergereicht
```

Tests: `cargo test --workspace` (Integrationstests brauchen `DATABASE_URL` auf eine Postgres-Instanz), im Web
`npm run lint && npm run typecheck && npm run build`.
