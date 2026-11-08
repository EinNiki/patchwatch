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

**Agent aktualisieren:** `sudo patchwatch-agent-update` lädt **nur das Binary** (nie ein Skript) der festgelegten
Hauptversion, prüft SHA256-Summe und Signatur, sichert die alte Datei (`patchwatch-agent.prev`), testet die neue vor dem
Austausch und fällt bei einem Fehler auf die alte zurück. Server-URL und Token bleiben. Eine neue Hauptversion wird nie
automatisch geladen; dafür bewusst `install.sh --version vX.Y.Z` ausführen (das setzt auch die Hauptversion neu). **Automatische Updates sind standardmäßig aus.** Einschalten: `install.sh --auto-update` (setzt
`auto_update=yes` in `/etc/patchwatch/update.conf` und aktiviert den wöchentlichen Timer; `--no-auto-update` schaltet
ab).

**Prüfung beim Installieren und Aktualisieren:** `install.sh` berechnet den SHA256 der heruntergeladenen Datei selbst und
vergleicht ihn mit dem Eintrag in der `.sha256`-Datei für genau diesen Dateinamen (fehlt er oder ist er nicht eindeutig,
Abbruch; kein `sha256sum -c`). Zusätzlich muss die minisign-Signatur (`.minisig`) zu dem im Skript eingetragenen
öffentlichen Schlüssel passen. Dafür wird das Paket `minisign` benötigt (`apt install minisign`). Fehlt der Schlüssel
oder minisign, wird **nichts installiert**.

### Release-Signatur einrichten (einmalig, Voraussetzung)

Warum minisign: ein einzelner kleiner öffentlicher Schlüssel (eine Zeile), im Skript fest eingetragen, ohne Online-Dienst
oder Transparenzlog (cosign „keyless“ bräuchte Sigstore zur Prüfzeit und ein größeres Werkzeug auf jedem Host); das Paket
ist in Debian und Ubuntu enthalten.

Bis das erledigt ist, **scheitern Installation und Update des Agents absichtlich** (Platzhalter `PW_PUBKEY`), und der
Release-Workflow bricht ab. Der Schlüssel wurde nicht erzeugt; der private Teil darf nie in das Repository.

1. Schlüsselpaar auf einem vertrauenswürdigen Rechner erzeugen (ohne Passwort, damit die CI ihn nutzen kann):
   `minisign -G -W -p patchwatch.pub -s patchwatch.key`
2. Inhalt von `patchwatch.key` als Repository-Geheimnis `MINISIGN_SECRET_KEY` hinterlegen (GitHub: Settings → Secrets and
   variables → Actions), danach die Datei sicher löschen oder offline aufbewahren.
3. Die **zweite Zeile** von `patchwatch.pub` (beginnt mit `RW`) in `agent/dist/install.sh` bei `PW_PUBKEY=` eintragen,
   dasselbe Skript nach `install.sh` im Wurzelverzeichnis kopieren (`cp agent/dist/install.sh install.sh`) und committen.
4. Release-Tag erzeugen. Der Workflow signiert `patchwatch-agent-*-linux` und veröffentlicht die `.minisig`-Dateien.
5. Bereits installierte Agents tragen den Schlüssel in `/usr/local/lib/patchwatch/verify.sh`: einmal `install.sh` neu
   ausführen, damit sie ihn bekommen.

Tests: `sh agent/tests/install_test.sh` (läuft in der CI; ohne Root und Netz, minisign wird durch eine Attrappe ersetzt).

`install.sh` lädt das Binary aus dem GitHub Release. Der Token liegt in `/etc/patchwatch/token` (`root:root 0600`) und wird per
systemd-`LoadCredential` an den Dienst `patchwatch` (kein `DynamicUser`) gereicht.
Konfiguration: `/etc/patchwatch/agent.toml`, Beispiel in `agent/dist/agent.toml.example`.

### Check-in und „Jetzt aktualisieren“

Ein zweiter systemd-Timer (`patchwatch-agent-checkin.timer`, minütlich) startet `patchwatch-agent checkin`. Der Agent
wartet per Long-Poll (`checkin_wait_secs`, Standard 40): „Jetzt aktualisieren“ erreicht den Agent so binnen Sekunden. Mit `checkin_wait_secs = 0` gilt stattdessen das Intervall aus `agent.toml` (`checkin_interval_secs`, Standard 300, 60–86400; `checkin_enabled = false`
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
docker compose logs server      # beim ersten Start: einmaliges Start-Passwort für "admin"
```

> **Netzwerk: patchwatch gehört nur ins Heimnetz oder hinter ein VPN.** Es ist ein Verwaltungswerkzeug mit
> Admin-Oberfläche und kein öffentlicher Dienst. Der mitgelieferte Caddy lauscht standardmäßig auf allen
> Schnittstellen (80/443); mit `PATCHWATCH_BIND=<LAN- oder VPN-Adresse>` in der `.env` wird er auf eine
> Adresse begrenzt. Nicht ohne weiteren Schutz (VPN, IP-Filter, Zugangsschutz am Proxy) ins Internet stellen.

**Erster Start und Admin-Passwort:** Es gibt kein festes Standardpasswort. Existiert noch kein Admin, legt der
Server `admin` an: entweder mit `PATCHWATCH_ADMIN_PASSWORD` (mind. 12 Zeichen, der frühere Standardwert wird
abgelehnt) oder, wenn nichts gesetzt ist, mit einem Zufallspasswort (32 Zeichen, CSPRNG), das **genau einmal auf
stderr** erscheint (`docker compose logs server`) und nie gespeichert wird. Ein erzeugtes Passwort muss beim ersten
Login geändert werden; bis dahin sind nur Passwortwechsel und Abmelden möglich. Bestehende Installationen, deren
Admin noch das frühere Standardpasswort hat, werden beim Start erkannt und müssen es beim nächsten Login ändern.
Anmeldeversuche sind je IP und je Konto auf 10 pro 10 Minuten begrenzt (danach `429` mit `Retry-After`). Weitere
Konten oder ein neues Passwort per Kommandozeile:
`docker compose exec -T -e PATCHWATCH_ADMIN_PASSWORD='…mind. 12 Zeichen…' server patchwatch-server create-admin ops`.

Host und Agent-Token anlegen (Web-UI folgt; bis dahin per API, Token wird nur einmal angezeigt
und serverseitig nur als SHA-256-Hash gespeichert):

```sh
curl -c jar -H 'content-type: application/json' -d '{"username":"admin","password":"…"}' https://patchwatch.example.org/api/v1/auth/login
curl -b jar -H "x-csrf-token: <csrf_token aus der Antwort>" -H 'content-type: application/json' \
     -d '{"name":"web1"}' https://patchwatch.example.org/api/v1/hosts
```

### Agent-Token ändern und prüfen

Der Token steht nie in einem Befehlsargument (sichtbar in `ps` und der Shell-History); `--token <wert>` wird abgelehnt.

```sh
sudo patchwatch-agent set-token                      # Eingabe ohne Echo
sudo patchwatch-agent set-token --stdin < datei      # aus Standardeingabe (nur eine Zeile)
sudo patchwatch-agent set-token --token-file /pfad   # aus Datei (kein Symlink)
sudo patchwatch-agent set-token --no-test            # ohne Test-Report
sudo patchwatch-agent set-token --migrate            # Token aus agent.toml nach /etc/patchwatch/token verschieben
patchwatch-agent status                              # Version, Konfiguration, Token-Herkunft, Fingerabdruck, Rechte, letzter Lauf
```

`set-token` prüft das Format (`pw_…`, 16–128 Zeichen aus `A-Za-z0-9_-`), schreibt atomar mit `0600 root:root` und sendet
danach einen Test-Report: „Token akzeptiert (Host: …)“, „Token abgelehnt (401)“ oder „Server nicht erreichbar“. Der Dienst
wird nicht neu gestartet; danach `sudo systemctl start patchwatch-agent`. Steht ein Token in `agent.toml`, meldet der Befehl das
und bietet `--migrate` an (Sicherung der Konfiguration ohne Token). `status` zeigt nur die ersten 8 Hex-Zeichen des SHA-256 als Fingerabdruck.
Lehnt der Server den Token ab, beendet sich der Agent mit Exit-Code 4 und einer Zeile im Journal. `install.sh` und
`patchwatch-agent-update` ändern weder Token noch Konfiguration; der Test-Lauf danach unterscheidet „Update ok, Report ok“,
„Update ok, Token abgelehnt“ und „Update fehlgeschlagen“.

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

**Ausgehende Proxys:** `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` werden für Benachrichtigungskanäle und Quellen-Spiegel
(alles, was die SSRF-Prüfung durchläuft) bewusst **ignoriert**: Ein Proxy würde die geprüfte, gepinnte Adresse umgehen.
Die Feeds der festen Standardquellen (Ubuntu, Debian, OSV, NVD, KEV) und OIDC laufen über den allgemeinen Client und
folgen den Proxy-Variablen; deren Ziele kommen nicht aus Benutzereingaben. Eine eigene, ebenfalls geprüfte
Proxy-Einstellung gibt es nicht; sie wäre nur mit Prüfung der Proxy-Adresse selbst sinnvoll.

### Profilbild

In der Seitenleiste steht vor dem Namen ein rundes Profilbild (28 px; eingeklappt nur das Bild, der Name als Tooltip).
Standard ist ein Kreis mit **Initialen**, lokal erzeugt: Farbe aus sechs festen Tokens (`--av-1` … `--av-6`, Kontrast
≥ 4,5:1 in Hell und Dunkel), deterministisch aus dem Benutzernamen. Es gibt keinen Gravatar, keinen externen Dienst und keine
frei wählbare Bild-URL.

Unter Einstellungen → Konto lässt sich ein eigenes Bild setzen („Profilbild ändern“, „Entfernen“):

- **Im Browser:** nur PNG, JPEG, WebP (Typ an den Bytes erkannt, nicht an der Endung; kein SVG, kein GIF), höchstens 2 MB,
  Zuschnitt auf 128 × 128 (Zoom und Verschieben), Neukodierung als WebP bzw. PNG, höchstens 64 KB.
- **Auf dem Server** (`PUT /api/v1/auth/avatar`, CSRF-Token, 10 Versuche je 10 Minuten): Es gibt **keine Bildbibliothek**
  (keine neue Angriffsfläche). Stattdessen wird nur das im Browser neu kodierte Bild streng geprüft: Signatur, Länge ≤ 64 KB,
  exakt 128 × 128, `Content-Type` passt zum Inhalt, bei PNG alle Chunk-Prüfsummen und nur Bild-Chunks, bei WebP nur
  `VP8`/`VP8L`/`VP8X`/`ALPH`; Text, EXIF, XMP, Animation und Anhängsel werden abgelehnt. Ein kleines Farbprofil (ICC, ≤ 4 KB)
  ist erlaubt, weil Chrome es an WebP anhängt. Der Server dekodiert nichts und kodiert nicht neu; wer die API direkt
  anspricht, kann also nur ein Bild speichern, das diese Prüfung besteht.
- **Speicherung:** in der Datenbank (`admin_users.avatar`, `bytea`, Migration `0018`). Auslieferung nur über
  `GET /api/v1/auth/avatar` für angemeldete Admins mit festem `Content-Type`, `X-Content-Type-Options: nosniff`,
  `Cache-Control: private`, `Content-Security-Policy: default-src 'none'`. Das Bild wird nie in die Seite eingebettet.

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
| Ubuntu `cves.json` | inkrementell | **Standard ist der Hybridmodus** (`PATCHWATCH_CVE_UBUNTU_MODE=hybrid`, Begründung und Messwerte in [docs/ubuntu-source.md](docs/ubuntu-source.md)): **täglich** je relevantem Release (Releases der Ubuntu-Hosts plus `PATCHWATCH_CVE_UBUNTU_BULK_RELEASES`) die Canonical-OVAL-Datei als bedingte Anfrage (`ETag`/`If-Modified-Since`, 304 = nichts zu tun), gestreamt entpackt und geparst (nie ganz im Speicher; Grenzen `PATCHWATCH_CVE_UBUNTU_OVAL_MAX_BYTES`, `..._OVAL_MAX_XML_BYTES`, `..._OVAL_TIMEOUT_SECS`; Weiterleitungen nur auf denselben Host). Übernommen werden nur **behobene Kernel-Einträge** mit Fixversion; fehlende oder nur „Kernel läuft“-Einträge bleiben „unbekannt“ (nie behoben oder nicht betroffen). **Stündlich** die ersten Seiten der API für offene Fälle: Seitengröße 20, bei Fehlern 10, dann 5 (nie darunter), nach fehlerfreien Läufen wieder größer, bei 422 wird das Maximum gelernt, `Retry-After` gilt (höchstens 15 Minuten), eine Anfrage gleichzeitig, `PATCHWATCH_CVE_UBUNTU_PAGE_PAUSE_MS` Pause (Standard 2000), Zeitlimit `PATCHWATCH_CVE_UBUNTU_PAGE_TIMEOUT_SECS` (Standard 90). Ein Ausfall der API ist kein Totalausfall: die Massendaten gelten weiter, aber nur innerhalb ihrer Frische, `max(3 × Intervall, 36 Stunden)`; danach zeigen die Hosts dieses Releases „CVE-Lage unbekannt“ (Rot bleibt Rot). Die Quelle ist erst **vollständig**, wenn für jedes relevante Release der letzte Import gelungen und frisch ist. Die Intervalle (täglicher Import, stündlicher Abruf, je mindestens 15 Minuten) stehen in den Einstellungen. Ein vorhandener Rückstandsabbau wird nicht gelöscht, sondern ruht (`feed_state.backfill_parked`) und läuft im Modus `api` weiter. **Es folgt die Beschreibung des Rückfallmodus `api`.** Die API hat **keinen** „updated since“-Filter. Es wird absteigend nach `updated` paginiert (20 CVEs, ca. 3,7 MB je Seite) und am gespeicherten Cursor gestoppt. Erstabruf: alles, was innerhalb des **Horizonts** (`PATCHWATCH_CVE_UBUNTU_HORIZON_DAYS`, Standard 365 Tage nach `updated`, `0` = ganze Liste) geändert wurde, verteilt auf mehrere Läufe; Watchlist-CVEs außerhalb davon werden einzeln nachgeladen. Pro Lauf höchstens `PATCHWATCH_CVE_UBUNTU_MAX_PAGES` Seiten (Standard 100). Der Fortschritt wird gespeichert, der nächste Lauf setzt per Offset dort fort (eine Seite Überlappung). Die Quelle gilt erst als vollständig, wenn der Horizont erreicht ist (bzw. bei späteren Rückständen der alte Cursor); bis dahin zeigt die Feed-Tabelle „Erstabruf läuft: Seite N von etwa M (Schätzung)“ bzw. „Rückstand wird abgebaut“, nie „Aktuell“, und Hosts werden nicht grün (siehe „Bewertungsregeln“). Wird eine Quelle gelöscht und neu angelegt, beginnt der Erstabruf von vorn. Eine Seite ist ca. 3,7 MB groß (169 Kernel-Pakete je CVE), auf dem Netz aber nur ca. 90 KB (gzip).  **Bei Drosselung oder Ausfall (429, 5xx, Timeout, Verbindungsabbruch):** je Seite 3 Versuche mit exponentiellem Backoff und Jitter, `Retry-After` (Sekunden oder Datum, höchstens 15 Minuten) hat Vorrang; danach endet der Lauf sauber, geladene Seiten bleiben gespeichert und der nächste Lauf setzt dort fort. Nach einem Fehllauf wartet der Scheduler 2, 5, 10, 30 Minuten (danach wieder das normale Intervall; ein Erfolg setzt zurück). Zwischen zwei Seiten liegt eine Pause (`PATCHWATCH_CVE_UBUNTU_PAGE_PAUSE_MS`, Standard 500), es läuft höchstens eine Anfrage gleichzeitig; der User-Agent nennt das Projekt. Ein Lauf ohne Fortschritt über `PATCHWATCH_CVE_STALL_TIMEOUT_SECS` (Standard 1800) wird abgebrochen und freigegeben. |
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

### Bewertungsregeln

Pro Host und CVE wird aus den Daten der Quellen (`cve_source_status`) und dem laufenden Kernel ein Status gebildet
(`server/src/cve/eval.rs`; die Regeln sind getestet):

| Quellenstand für Release und Kernelpaket | Ergebnis |
|---|---|
| Behoben in Version V, der laufende Kernel ist ≥ V | behoben (nicht gespeichert) |
| Behoben in V, der laufende Kernel ist älter, ein installierter neuerer Kernel ist ≥ V | Neustart nötig |
| Behoben in V, weder laufender noch installierter Kernel erreicht V | **verwundbar** |
| Behoben, aber ohne gültige Fix-Version | unbekannt |
| Offen (`needed`, `ignored`, `deferred`) | **verwundbar** |
| **Fix angekündigt, aber nicht veröffentlicht (Ubuntu `pending`)** | **verwundbar**, Begründung „verwundbar, Fix in Arbeit (voraussichtlich in V), noch nicht veröffentlicht“ |
| Nicht betroffen | nicht betroffen (nicht gespeichert) |
| Unklar, kein Eintrag, ungültige Version, Proxmox-Kernel | unbekannt, nie „behoben“ |

Die Regel zu „Fix angekündigt“ gilt seit Commit `fd5ed39`: Solange der Fix nicht veröffentlicht ist, ist der Host
verwundbar (wie auf ubuntu.com „Vulnerable“). Deshalb erscheint ein angekündigter Fix in Host-Status, Host-Liste,
CVE-Liste und Benachrichtigungen als **verwundbar**; der Zähler „Fix angekündigt“ bleibt in der Oberfläche vorhanden, wird
für neue Bewertungen aber nicht mehr erzeugt. Der Fix-Filter „offen“ der CVE-Liste umfasst verwundbar und angekündigt,
„behoben“ nur veröffentlichte Fixes. Zeilen abgeschalteter oder gelöschter Quellen werden bei der Bewertung ignoriert
(seit `0cd2c5e`, `reeval.rs`).

**Anzeige im CVE-Fenster („Fix im Archiv“ und „Fix in Arbeit“).** Beide Angaben stammen aus verschiedenen Quellen und
dürfen sich nicht widersprechen: „Fix im Archiv“ zählt nur **veröffentlichte** Fixes (Quellenstatus ungleich `fix_pending`;
Server: `open_with_fix` in `routes/hosts.rs`), „Fix in Arbeit“ ist der angekündigte, noch nicht veröffentlichte Fix.
Ein angekündigter Fix wird nie als bestätigter Fix gezeigt: Die Zeile trägt den Zusatz „(angekündigt)“, und der
Tooltip „Fix im Archiv“ erscheint nur bei veröffentlichten Fixes. Das Detail unterscheidet den Stand des Trackers (Quelle)
vom apt-Kandidaten des Hosts (`/hosts/{id}/updates`): Der Kandidat belegt, dass ein Paketupdate bereitsteht, ersetzt aber
nicht die Fix-Version des Trackers. `eval.rs` bleibt unverändert.

**Debian: Archiv und Security.** Der Debian Security Tracker führt je Release EINEN Status und EINE Fix-Version und je Suite
(`trixie`, `trixie-security`) die Version des Quellpakets. Der Adapter legt je Suite Version und Status ab
(`cve_source_status.suites`): Suite-Version ≥ Fix-Version = gefixt, darunter verwundbar. Die Bewertung eines Hosts bleibt
dieselbe Regel wie oben (Vergleich des laufenden Kernels mit der Fix-Version, `eval.rs` unverändert): Ein Host, dessen Kernel
unter der Fix-Version liegt, ist **verwundbar**, auch wenn die Security-Suite den Fix schon enthält; die Host-Ansicht
zeigt dann „Fix verfügbar über Security-Updates“, bis der Host die Version installiert hat. Ob ein Host das Security-Archiv
aktiviert hat, ist nicht bekannt.

Grün (kein offener CVE-Befund) zeigt ein Host nur, wenn alle zuständigen Quellen nutzbar sind (siehe nächster
Abschnitt); sonst „CVE-Lage unbekannt“ mit Begründung.

### Filter

Die CVE-Seite filtert je Distribution (Debian, Ubuntu) nach „gefixt“, „offen“ oder „egal“. Filter und Anzeige benutzen
**dieselbe Definition der Chips** (`chips_sql` in `server/src/routes/cves.rs`): ein Chip je (Quelle, Release), sein Status ist der
ungünstigste aller Pakete (verwundbar, dann Fix angekündigt, unbekannt, gefixt); bei Releases, die auf einem Host laufen, zählen
nur die Pakete, auf die sich die Bewertung der Hosts stützt.

- **gefixt** = mindestens ein Release der Distribution auf einem deiner Hosts hat einen Chip „gefixt“. Bei Debian gilt ein
  Release als gefixt, wenn die Security-Suite **oder** das Archiv die Fix-Version enthält; eine CVE, die nur im Archiv offen,
  aber in Security gefixt ist, zählt als „gefixt“.
- **offen** = mindestens ein Release auf einem deiner Hosts hat einen Chip „verwundbar“ oder „Fix angekündigt“. Bei Debian:
  weder Security noch Archiv enthält die Fix-Version (z. B. nur in einem Zwischenarchiv).
- Chips anderer Releases (Release läuft auf keinem deiner Hosts) sind gestrichelt und gedämpft; die Legende darüber
  erscheint nur, wenn ein solcher Chip auf der Seite steht.
- **egal** = keine Bedingung. Debian und Ubuntu sind mit **UND** verknüpft.
- **Fester Bezug auf deine Hosts** (kein Auswahlfeld mehr): Die Filter „Debian/Ubuntu gefixt/offen“ und „Betrifft meine Hosts“
  beziehen sich ausschließlich auf Releases, die auf mindestens einem Host laufen. In der Spalte „Distributionen“ stehen zuerst
  die Chips dieser Releases; alle anderen stehen eingeklappt unter „+ N weitere Releases“ (gestrichelt, gedämpft, Tooltip „Läuft
  auf keinem deiner Hosts“), ohne Einfluss auf Filter und Sortierung; Aufklappen bleibt möglich. Die Legende über der Tabelle
  sagt: „Filter berücksichtigen nur Releases deiner Hosts.“ Der alte URL-Parameter `releases=` wird von der Oberfläche ignoriert.
  Eine CVE, die nur in einem Release ohne eigenen Host gefixt ist, wird deshalb nicht als „gefixt“ gefunden. Findet ein Filter
  nichts, nennt die Seite die aktiven Filter und bietet „Filter zurücksetzen“ an. Die API behält `releases=all` unverändert für
  andere Clients und Tests (unbekannte Werte gelten als `mine`, kein Fehler).
- **Betrifft** (Auswahlfeld in der Filterzeile, `?affects=all` in der URL, Standard „Meine Hosts“, Alternative „Alle“): „Meine Hosts“ zeigt nur CVEs, bei
  denen **mindestens ein Host** den Zustand *verwundbar*, *Fix angekündigt* oder *Neustart nötig* hat. *Unbekannt* (z. B.
  Proxmox), *gefixt* und *nicht betroffen* zählen nicht; unbekannte Hosts werden in der Spalte „Hosts“ trotzdem genannt.
  Beobachtete CVEs (Watchlist) und die gezielte Suche zeigen unabhängig davon alles. Über der Tabelle steht „N CVEs betreffen
  deine Hosts“ als reiner Text (die Zahl gilt für die übrigen Filter). Ist die Liste im Standard
  leer, steht „Keine CVE betrifft deine Hosts“ mit dem Textlink „Alle CVEs anzeigen“, der das Feld auf „Alle“ stellt.
- **Sortierung** (`?sort=`, serverseitig, feste Liste): Standard `hosts` = zuerst die CVEs mit den meisten betroffenen Hosts, dann
  Level (hoch zuerst), dann die neuere Veröffentlichung; die Spalte „Hosts“ sortiert danach (Pfeil kehrt um). Daneben `latest`
  (Veröffentlichung), `level` und `updated`. Beobachtete CVEs stehen immer oben. „Weitere laden“ holt die nächste Seite aus
  derselben festen Reihenfolge (Tiebreak: CVE-ID), nichts springt.
- **Aktualisiert** (Spalte, Sortierung `updated`) ist die **letzte Änderung laut Quelle**, bei mehreren Quellen die neueste
  (`cves.source_updated_at`). Liefert keine Quelle ein Datum, steht „unbekannt“, nie der Importzeitpunkt. Daten liefern die Ubuntu-API
  (`updated_at`), NVD (`lastModified`) und OSV (`modified`); die Ubuntu-OVAL-Massendaten und der Debian Security Tracker enthalten kein
  Änderungsdatum. Der Importzeitpunkt steht getrennt als „Zuletzt abgeglichen“ (`cves.last_synced_at`, Tooltip und CVE-Detail).
  Ein erneuter Import ändert „Aktualisiert“ nicht. Bestehende Zeilen behalten ihre Daten (Migration 0016 ist additiv); ein Quelldatum
  lässt sich aus den gespeicherten Rohdaten nicht rekonstruieren und wird beim nächsten Import der Quelle nachgefüllt, sofern sie eines liefert.
- **Zeiten** erscheinen in der Oberfläche in **Europe/Berlin** (absolut im Tooltip), unabhängig von Server (UTC) und Browser; „vor n Tagen“
  zählt Berliner Kalendertage, auch über den Sommerzeitwechsel. Die **Uptime** der Hosts wird aus der Bootzeit berechnet
  (Reportzeit minus vom Agenten gemeldete Uptime) und läuft zwischen den Reports weiter; die Host-Seite nennt die Bootzeit („gestartet 06.11. 22:27“).
- **Zusammenspiel**: *Debian/Ubuntu* filtern über die Chips der Releases deiner Hosts. *Betrifft* filtert über die Hosts und ist
  davon unabhängig; beide sind mit **UND** verknüpft.
- Der Filter hängt am **Typ** der Quelle (`debian`, `ubuntu`), nicht an ihrer stabilen ID; abgeschaltete oder gelöschte Quellen
  behalten ihre Daten, die weiter angezeigt und gefiltert werden.

### Abruf-Läufe der CVE-Quellen

Jeder Abruf (Zeitplan, „Jetzt abrufen“ je Quelle, „Alle abrufen“) ist ein **Lauf** in der Tabelle `feed_runs`
(Migration `0017`, nur additiv). Ein Lauf durchläuft die Phasen *Verbinden → Herunterladen → Auswerten → Speichern →
Hosts prüfen → Fertig*; Dauer je Phase, Bytes, Einträge und Hosts werden mitgeschrieben, nie Antwortinhalte oder Schlüssel.
Je Quelle bleiben die letzten 50 beendeten Läufe.

| Endpunkt | Wirkung |
| --- | --- |
| `POST /api/v1/feeds/{id}/run` (`{confirm?}`) | `202 {run}`; `409 {code:"running", run_id}` hängt sich an den laufenden Lauf an; `428 {code:"backoff"}` verlangt Bestätigung (`confirm:true`); `429 {code:"too_soon"\|"backoff_limited", retry_after}` |
| `POST /api/v1/feeds/refresh` | alle aktiven Quellen nacheinander: `202 {runs, running, skipped}` oder `409` |
| `GET /api/v1/feeds/runs?active=true` | laufende und vor <30 s beendete Läufe; mit `?source=&limit=` der Verlauf |

Regeln: mindestens **60 s** zwischen zwei Abrufen derselben Quelle; in der Wartezeit nach Fehlern (Backoff) braucht ein
manueller Abruf eine Bestätigung und ist auf **einen Versuch je 5 Minuten** begrenzt. Pro Quelle läuft höchstens ein Lauf
(eindeutiger Teilindex); die Läufe mehrerer Quellen laufen nacheinander.
Fortschritt kommt als Live-Ereignis `feed_run` (höchstens 2 je Sekunde), die Oberfläche fragt zusätzlich alle 3 s nach,
solange ein Lauf aktiv ist.

**Ursache von „Ein Abruf läuft bereits“:** Der alte Abruf hielt eine globale Sperre für *alle* Quellen, solange irgendeine
Quelle lud, speicherte oder Hosts bewertete. Nur das Laden hatte einen Fortschrittswächter; Speichern und Bewerten hatten
keine Obergrenze, und der Knopf lieferte in dieser Zeit nur den 409-Fehler ohne Hinweis, was läuft. Jetzt gilt: Herzschlag
je Lauf, eine harte Obergrenze (4 × `CVE_STALL_TIMEOUT_SECS`), beim Start werden verwaiste Läufe als „unterbrochen“
markiert (`sweep_stale`), und ein zweiter Klick zeigt den laufenden Lauf an, statt einen Fehler.

### Grenzen der CVE-Bewertung

- **Proxmox-Kernel (`-pve`) haben keine belastbare CVE-Quelle.** Sie werden immer als **UNKNOWN** bewertet („manuell
  prüfen“, Link zu den [Proxmox Security Advisories](https://forum.proxmox.com/forums/security-advisories.26/)),
  nie als „grün“, und lösen **keinen** ntfy-Alarm aus. Im UI lässt sich „geprüft am …“ setzen; die Markierung
  verfällt, sobald sich der laufende Kernel ändert.
- UNKNOWN gilt auch bei fehlender Datenlage (kein Eintrag im Tracker, Quellpaket nicht zuordenbar, unbekannter
  Status, ungültige Version), nie „behoben“.
- Ubuntu-Status `ignored` und `deferred` zählen als verwundbar (der Hersteller behebt nicht). Ubuntu `DNE` wird ignoriert.
- Eine CVE-Quelle ist nur nutzbar, wenn sie eingeschaltet ist, mindestens einen **vollständigen** Abruf hatte (kein offener Erstabruf/Rückstand), der letzte Erfolg nicht älter ist als max(3 × Intervall, 6 h) und kein Dauerfehler (3 Fehlschläge in Folge) vorliegt. Ohne nutzbare Quelle der Distribution (oder wenn eine eingeschaltete Quelle nicht nutzbar ist) zeigt der Host „CVE-Lage unbekannt“ mit Begründung („Quelle X unvollständig / veraltet / fehlerhaft“), nie grün. Bereits bekannte verwundbare CVEs bleiben sichtbar („Rot bleibt rot“).
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
  Releases, die auf deinen Hosts laufen („+ n weitere Releases“ blendet den Rest ein). Filter:
  Distribution sowie „Debian gefixt, Ubuntu offen“ und umgekehrt. `/cves/<ID>` zeigt Quellen-Links, letzte Änderung und
  betroffene Hosts.
- **Host-Detail, CVE-Lage**: ein Satz als Entscheidungshilfe („Nach dem Neustart auf 7.0.0-42.42 sind noch 81 CVEs
  offen, 2894 werden behoben.“; ohne nötigen Neustart „81 CVEs offen, kein Fix installiert.“; ohne offene „Keine
  offenen CVEs.“), ein gestapelter Balken und drei Kacheln: **Offen** (kein Fix installiert; darunter, wie viele einen Fix im
  Archiv haben), **Neustart nötig** (Fix installiert, läuft erst nach dem Neustart), **Gefixt**; „Unbekannt“
  als kleiner Zähler. „Nicht betroffen“ wird in der Host-Ansicht nicht angezeigt (die API liefert die Zahl weiter; eine alte
  URL mit `?cve=not_affected` öffnet die Standardansicht). Jede Kachel zeigt Zahl, Wort, Icon und eine Zeile, die aktive ist per Rahmen und Haken markiert. Es
  steht immer nur **eine** Liste da (Standard „Offen“): nach Level (hoch zuerst), dann Alter sortiert; „Neustart nötig“ und
  „Gefixt“ sind nach Fix-Version gruppiert (neueste zuerst, „Gefixt“ eingeklappt, „Alle anzeigen“ klappt alles auf).
  Suche (CVE-ID und Text) und Level-Filter gelten für die aktive Liste. Die Kernel-Zeile zeigt laufenden und neuesten
  installierten Kernel; „Befehl kopieren“ legt `sudo reboot` in die Zwischenablage und führt nichts aus. Beim Scrollen
  bleibt eine verkürzte Leiste mit den Zählern stehen. Ein Eintrag ohne Fix-Version zählt nie als „Fix installiert“.
  Ist die zuständige Quelle eingeschränkt, steht über der Liste ein Hinweis (z. B. „Ubuntu: Offene Fälle nicht vollständig
  geladen (API überlastet, seit 22:08) …“), die Kachel „Offen“ trägt ein Warnsymbol und „kann unvollständig sein“; nie
  „alles gut“. Proxmox-Hosts bleiben „unbekannt, manuell prüfen“ (nie grün).
- **Agents**: Tabelle mit Hostname, Distribution, Agent-Version, letztem Report und Check-in; „Jetzt aktualisieren“,
  „Token erneuern“, Löschen mit Bestätigung. „Agent hinzufügen“ zeigt den Token einmalig und einen Installationsbefehl
  **ohne** Token (`install.sh` fragt ihn ohne Echo ab).
- **Benachrichtigungen**: ntfy, Matrix, Gotify, Discord und „Live im Browser“, je mit Zugangsdaten (write-only),
  Ereignisauswahl und Testnachricht.
- **Einstellungen**: Passwort ändern, Farbschema, Aufbewahrung der Report-Historie (7–3650 Tage).
- Änderungen erscheinen live (WebSocket, siehe oben) ohne Neuladen; Meldungen des Browser-Kanals und Ergebnisse von Aktionen als Toast (oben rechts).

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

### Ubuntu-Erstabruf: Umfang und Entscheidung

Die Ubuntu-API hat keinen „updated since“-Filter, `limit` ist auf 20 begrenzt. Gemessen: 22.307 CVEs ≈ 1.116 Seiten, ca. 90 KB je Seite im Netz (gzip, ca. 3,7 MB entpackt, 169 Kernel-Varianten je CVE), insgesamt ca. 100 MB Übertragung und ca. 5,6 Mio. gespeicherte Statuszeilen bei vollständigem Abruf; Antwortzeit 0,2–30 s je Seite. Bei 100 Seiten je Lauf und 60 Minuten Intervall sind das ca. 12 Läufe (ca. 12 Stunden) für die ganze Liste. Etwa 4.000 CVEs wurden in der letzten Woche geändert (Sammelaktualisierungen), ein kurzer Horizont spart daher kaum Seiten; 365 Tage decken ca. 95 % der Liste ab. **Entscheidung:** Horizont = konfigurierbares Alter nach `updated`, Standard 365 Tage; `PATCHWATCH_CVE_UBUNTU_HORIZON_DAYS=0` lädt alles. Ein Filter `package=linux` reduziert die Treffer von 85.337 auf 22.307, die Liste der anderen Kernel-Varianten ist kleiner (z. B. azure 20.597), aber die Records enthalten alle Varianten; vollständig belegt ist die Auslassungsfreiheit nicht, deshalb wird der Filter **nicht** verwendet.
