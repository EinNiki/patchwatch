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

**Agent aktualisieren:** `sudo patchwatch-agent-update` (lädt die neueste Version, prüft die SHA256-Summe, behält
Server-URL und Token). Bei Agents ohne diesen Befehl einmal den Installationsbefehl erneut ausführen – Server-URL
und Token werden aus `/etc/patchwatch` übernommen. Mit `--auto-update` prüft ein wöchentlicher Timer selbst auf
neue Versionen (`--no-auto-update` schaltet ihn ab).

`install.sh` lädt das Binary aus dem GitHub Release und prüft die SHA256-Summe vor der
Installation. Der Token liegt in `/etc/patchwatch/token` (`root:root 0600`) und wird per
systemd-`LoadCredential` an den Dienst `patchwatch` (kein `DynamicUser`) gereicht.
Konfiguration: `/etc/patchwatch/agent.toml`, Beispiel in `agent/dist/agent.toml.example`.

### Check-in und „Jetzt aktualisieren“

Ein zweiter systemd-Timer (`patchwatch-agent-checkin.timer`, minütlich) startet `patchwatch-agent checkin`. Der Agent
hält das Intervall aus `agent.toml` selbst ein (`checkin_interval_secs`, Standard 300, 60–86400; `checkin_enabled = false`
schaltet ihn ab) und fragt `POST /api/v1/agent/checkin`. Die Antwort ist ausschließlich `{"report_requested": true|false}`:
**keine Befehle, Pfade oder Skripte vom Server, kein offener Port am Host.** Nur bei `true` sendet der Agent einen Report.
In der UI (Seite „Agents“) fordert „Jetzt aktualisieren“ bzw. „Alle aktualisieren“ einen Report an; ein „Ja“ wird pro
Anforderung genau einmal ausgegeben (Wiederholung nach 10 Minuten ohne Report), pro Host höchstens eine Anforderung je Minute.

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

### Benachrichtigungskanäle

ntfy, Matrix, Gotify, Discord-Webhook und „Live im Browser“ werden in der UI eingerichtet und in der Datenbank
gespeichert. Je Kanal: an/aus, Zugangsdaten, Testnachricht und Ereignisse (Host-Status, Agent still, neue CVE auf
der Watchlist, Fix verfügbar, Feed-Fehler, Tageszusammenfassung mit Uhrzeit/Zeitzone). Die `PATCHWATCH_NTFY_*`-Variablen
bleiben als Voreinstellung; Werte aus der UI haben Vorrang.

- **`PATCHWATCH_SECRET_KEY`** (32 Byte, base64; `openssl rand -base64 32`) verschlüsselt Tokens und Webhook-URLs
  (XChaCha20-Poly1305, der Kanalname ist authentifizierte Zusatzinformation). **Sichere den Schlüssel getrennt von
  der Datenbank** – geht er verloren, sind gespeicherte Geheimnisse unlesbar und müssen neu eingegeben werden.
  Ohne Schlüssel lässt sich kein Geheimnis speichern. Geheimnisse sind write-only: die API liefert nur „gesetzt“.
- **SSRF-Schutz**: Ziele müssen öffentlich erreichbar sein (kein Loopback, privat, link-local, CGNAT …), es gibt keine
  Redirects, Timeouts sind kurz, die Antwort der Gegenseite wird nie gelesen. Testnachrichten melden nur
  `ok`, `nicht erreichbar` oder `HTTP <Code>`.
- **`PATCHWATCH_NOTIFY_ALLOWED_HOSTS`** erlaubt interne Ziele (z. B. `gotify.lan,10.0.0.5`) – nur exakte Hosts/IPs,
  keine Wildcards. Loopback und `169.254.0.0/16` (inkl. Metadaten-IP) bleiben immer gesperrt.

### Live-Updates (WebSocket)

`GET /api/v1/live` schiebt kleine Ereignisse (`report_received`, `host_status`, `host_cve_status`, `report_requested`,
`checkin`, `notification`, `resync`) an die UI; die UI lädt Daten danach über die REST-API nach. Der Endpunkt ist
nur mit gültiger Session erreichbar (sonst 401), die `Origin` muss zum `Host`-Header passen oder in
`PATCHWATCH_ALLOWED_ORIGINS` stehen (sonst 403), eingehende Nachrichten werden ignoriert, die Session wird
minütlich neu geprüft, maximal 64 gleichzeitige Verbindungen. Ein Reverse Proxy muss WebSocket-Upgrades für `/api/*` durchreichen (Caddy tut das).

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
Feed-Zustand je Quelle („veraltet seit …“).

**UI v2** (Seitenleiste: Hosts · CVEs · Agents · Benachrichtigungen · Einstellungen):

- **CVEs**: Spalte „Distributionen“ mit einem Chip je Quelle und Release (Icon + Text + Fix-Version). Standard sind nur
  Releases, die auf deinen Hosts laufen („+ n weitere Releases“ bzw. „Alle Releases“ blendet den Rest ein). Filter:
  Distribution sowie „Debian gefixt, Ubuntu offen“ und umgekehrt. `/cves/<ID>` zeigt Quellen-Links, letzte Änderung und
  betroffene Hosts.
- **Agents**: Tabelle mit Hostname, Distribution, Agent-Version, letztem Report und Check-in; „Jetzt aktualisieren“,
  „Token erneuern“, Löschen mit Bestätigung. „Agent hinzufügen“ zeigt den Token einmalig und einen Installationsbefehl
  **ohne** Token (`install.sh` fragt ihn ohne Echo ab).
- **Benachrichtigungen**: ntfy, Matrix, Gotify, Discord und „Live im Browser“, je mit Zugangsdaten (write-only),
  Ereignisauswahl und Testnachricht.
- **Einstellungen**: Passwort ändern, Farbschema, Aufbewahrung der Report-Historie (7–3650 Tage).
- Änderungen erscheinen live (WebSocket, siehe oben) ohne Neuladen; Meldungen des Browser-Kanals als Toast.

Die Matrix über Hosts und CVEs kommt später als Umschalter „Liste | Matrix“ auf der CVE-Seite.

Design und Barrierefreiheit sind in [`web/DESIGN.md`](web/DESIGN.md) festgelegt (Palette mit gemessenen Kontrasten,
Schriften, Statusdarstellung: immer Icon + Text + Farbe, nie „grün“ bei fehlender Datenlage). Hell/Dunkel folgt dem System.
Mit axe-core gegen Hell, Dunkel und Mobil geprüft: keine Verstöße.

### Betrieb mit TLS

`docker compose up -d` startet Postgres, Server, Web und den Caddy-Proxy (`/api` → Server, alles andere → Web;
`PATCHWATCH_DOMAIN` in `.env` setzen, sonst `localhost`). Hinter einem eigenen Proxy startet
`docker compose up -d postgres server web`: `/api/*` an `127.0.0.1:8080`, der Rest an `127.0.0.1:3000`, und dem Server
`PATCHWATCH_TRUST_PROXY=true` geben (siehe `deploy/Caddyfile`).

### UI als Produktionsbuild starten (schnell)

`npm run dev` (`next dev`) ist für die Entwicklung gedacht und deutlich träger: ungebündelte Module (~800 KB statt ~175 KB
JavaScript je Seite), Kompilierung beim ersten Aufruf, Entwicklungs-Overlay. Zum Ausprobieren und Messen der echten
Geschwindigkeit die UI als Produktionsbuild starten:

```sh
cd web
npm run build
npm run start:prod        # http://0.0.0.0:3100, leitet /api (inkl. WebSocket) an PATCHWATCH_API_URL (Standard http://127.0.0.1:8080)
PORT=3200 PATCHWATCH_API_URL=http://127.0.0.1:8080 npm run start:prod
```

`start:prod` ersetzt lokal den Reverse-Proxy (komprimiert Text, reicht `/api` und den Live-WebSocket durch); im Betrieb
übernimmt das Caddy (`encode zstd gzip`) bzw. das Docker-Image. Messwerte und Messskripte: [`docs/perf.md`](docs/perf.md).

### Entwicklung

```sh
docker run -d --name pw-pg -e POSTGRES_USER=patchwatch -e POSTGRES_PASSWORD=dev -e POSTGRES_DB=patchwatch -p 127.0.0.1:5432:5432 postgres:17-alpine
export PATCHWATCH_DATABASE_URL=postgres://patchwatch:dev@127.0.0.1:5432/patchwatch PATCHWATCH_COOKIE_SECURE=false
cargo run -p patchwatch-server -- create-admin admin      # Passwort per stdin oder PATCHWATCH_ADMIN_PASSWORD
cargo run -p patchwatch-server                             # API auf :8080
python3 scripts/dev-seed.py http://127.0.0.1:8080 admin    # Beispielhosts und -reports
cd web && npm ci && npm run dev                            # UI auf :3000, /api wird an :8080 weitergereicht
```

Der Live-WebSocket läuft in der Entwicklung direkt gegen die API (Next.js leitet keine Upgrades weiter):
`NEXT_PUBLIC_PATCHWATCH_LIVE_PORT=8080 npm run dev` und dem Server die UI-Origin erlauben, z. B.
`PATCHWATCH_ALLOWED_ORIGINS=http://localhost:3000`. In Produktion läuft alles über dieselbe Origin (Caddy).

Tests: `cargo test --workspace` (Integrationstests brauchen `DATABASE_URL` auf eine Postgres-Instanz), im Web
`npm run lint && npm run typecheck && npm run build`.

## Anmeldung per OpenID Connect

Zusätzlich zum Passwort lässt sich ein OIDC-Provider (Authentik, Keycloak, Google, Entra ...) einrichten. Variablen siehe
`.env.example` (`PATCHWATCH_OIDC_*`). Der Ablauf ist Authorization Code mit PKCE, nonce und einem state-Cookie.
Angemeldet wird nur, wer in `PATCHWATCH_OIDC_ALLOWED_EMAILS` oder `PATCHWATCH_OIDC_ALLOWED_DOMAINS` steht und eine
verifizierte E-Mail-Adresse hat; ohne Allow-List startet der Server nicht. SSO-Benutzer erscheinen als `oidc:<email>`
und haben kein Passwort. Die Signatur des ID-Tokens wird nicht geprüft, weil er direkt vom Token-Endpunkt über TLS kommt
(OIDC Core 3.1.3.7); Aussteller, Zielgruppe, Ablauf und nonce werden geprüft.
