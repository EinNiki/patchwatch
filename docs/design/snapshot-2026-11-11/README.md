# Design-Snapshot 2026-11-11

Stand der Oberfläche vom 11.11.2026: Tabellen als Karten über die volle Breite (Hosts, Agents, CVEs, CVE-Quellen),
Quellenbereich mit Knopfreihe und vier sichtbaren Aktionen je Quelle, Statuspillen.
Die älteren Stände bleiben unangetastet: [`../v1`](../v1/README.md) (Tag `design-v1`) und [`../v2`](../v2/README.md).

- **Tag:** `design-v2-2026-11-11` (annotiert)
- **Dateien:** `DESIGN.md` und `tokens.css` sind Kopien aus `web/` zum Zeitpunkt des Tags; `screenshots/` zeigt
  Hosts, Host-Detail, CVEs (auch mit geöffnetem Filterfenster), Agents, Einstellungen, Benachrichtigungen und Login
  bei 1440 und 390 px, hell und dunkel (Dateinamen `<seite>-<breite>-<light|dark>.png`).
- Die Bilder stammen aus einem Wegwerf-Stack mit Demo-Daten (`scripts/dev-seed.py`, Hosts `web-01`, `db-01` …),
  nicht aus echten Hosts. Höhe auf 950 px gekürzt, damit der Ordner klein bleibt.

## Stand wiederherstellen und starten

```sh
git fetch origin tag design-v2-2026-11-11
git checkout design-v2-2026-11-11          # losgelöster HEAD; für eigene Arbeit: git switch -c mein-zweig
docker compose up -d --build               # Server und Web, siehe README im Wurzelverzeichnis
# oder lokal: cargo build -p patchwatch-server, dann im Ordner web/: npm ci && npm run build && npm run start:prod
```

## Screenshots neu erzeugen

```sh
# 1. Wegwerf-Datenbank und Server (Port 8081), Admin anlegen, Demo-Daten einspielen:
PATCHWATCH_ADMIN_PASSWORD=… patchwatch-server create-admin admin
PATCHWATCH_ADMIN_PASSWORD=… python3 scripts/dev-seed.py http://127.0.0.1:8081 admin
# 2. Web gegen diesen Server (Port 3200) und optional die CVE-Feeds laden (POST /api/v1/feeds/refresh):
PORT=3200 PATCHWATCH_API_URL=http://127.0.0.1:8081 npm --prefix web run start:prod
# 3. Aufnahmen:
PW_MODULE=/pfad/zu/playwright PW_CHROME=/pfad/zu/chrome PW_PASSWORD=… PW_BASE=http://127.0.0.1:3200 PW_MAX_HEIGHT=950 \
PW_PAGES="hosts=/,host-detail=/hosts/host:web-01,cves=/cves,cves-filter=/cves,agents=/agents,settings=/settings,notifications=/notifications" \
  node scripts/screenshots.mjs docs/design/snapshot-2026-11-11/screenshots
```
