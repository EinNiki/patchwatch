# Nachtlauf 2026-11-12: Bericht

## 1 Gesamtstatus: GELB

Der Nachtlauf hat **nur gelesen und berichtet, keinen Code geändert**. Builds, Tests, Browser, Docker und Datenbank
wurden nach der Speicherregel übersprungen: Der Swap lag die ganze Nacht bei 53 bis 58 % (Schwelle 50 %), belegt
durch die ruhenden Prozesse der UI-Sitzung (zwei Debug-Server mit zusammen ca. 2 GB). Sie zu beenden hat die
Rechteprüfung der Umgebung abgelehnt. Dazu kam ein Nutzungslimit (00:19 bis 04:10 UTC stand der Lauf).

| Phase | Status |
|---|---|
| Warten auf UI-Sitzung | fertig (23:59 UTC, sauber, alles auf origin/dev 8cf3064) |
| 0 Sicherung, Branch | fertig |
| 1 UI-Restarbeiten | nur am Code geprüft, nichts gebaut (docs/overnight/phase1.md) |
| 2 Qualitätsschranken | teilweise: `cargo fmt --check`, `npm run lint`, `npm run typecheck` grün; clippy, cargo test, npm test, build, musl, Docker übersprungen |
| 3 Responsiv | übersprungen (Browser) |
| 4 Funktionstests | übersprungen (Stack, Browser, Datenbank) |
| 5 Daten, Zeit, Robustheit | nur Code-Review (docs/overnight/phase5.md) |
| 6 Agent, Deployment | nur Dateiprüfung (docs/overnight/phase6.md) |
| 7 Sicherheit | fertig, nur lesend (docs/overnight/security.md) |
| 8 Push | NICHT gepusht: Die Rechteprüfung der Umgebung hat den Push abgelehnt. Der Branch liegt nur lokal. |

## 2 Zuerst lesen

Keine kritischen Funde, keine roten Tests (es liefen aber fast keine). Mittlere Sicherheitsfunde, alle offen:

- **NVD-Schlüssel folgt einer geänderten Spiegel-URL** (`server/src/routes/feeds.rs:669-676`): Die Adresse einer
  Quelle lässt sich ändern, ohne dass das gespeicherte Geheimnis verworfen wird, auch auf `http://`. Braucht eine
  Admin-Sitzung. Altbestand vor dem Audit-Commit.
- **`POST /feeds/refresh?wait=true` umgeht Mindestabstand, Backoff-Bestätigung und Lauf-Protokoll**
  (`feeds.rs:906, 968-990`). Vom Dirigenten nachgelesen.
- **`install.sh` ist nicht signiert**; der in der Oberfläche gezeigte Befehl führt es mit sudo aus
  (`web/src/lib/agentCommands.ts:5`). Nicht nachgeprüft.
- Hoch in Phase 6, aber bekannt und gewollt: `PW_PUBKEY` in `install.sh:97` ist noch Platzhalter; Installation,
  Update und Release des Agents scheitern, bis der Schlüssel eingetragen ist.

Diese Prüfung war keine Vollprüfung und ersetzt den unabhängigen Opus-Audit in frischer Sitzung nicht.

## 3 Zahlen je Phase

| Phase | gefunden | behoben | offen |
|---|---|---|---|
| 1 (Code) | 4 Punkte nur teilweise umgesetzt, 4 Auffälligkeiten | 0 | 8 |
| 2 | 0 (drei Prüfungen grün) | 0 | 0 |
| 3, 4 | nicht geprüft | - | - |
| 5 (Code) | 13 (0 hoch, 4 mittel, 9 niedrig) | 0 | 13 |
| 6 (Dateien) | 20 (1 hoch, 4 mittel, 9 niedrig, 6 Hinweise) | 0 | 20 |
| 7 | 21 (0 kritisch, 0 hoch, 3 mittel, 18 niedrig) | 0 | 21 |

Nichts wurde behoben: Ohne Tests und Browser lässt sich kein Fix belegen ("ein Fehler = ein Commit mit Test").

## 4 Die schwersten drei Funde

1. NVD-Schlüssel geht an eine geänderte Spiegel-URL (siehe oben, security.md M1).
2. Doppelte Paketnamen im Report führen zu 500 und einem dauerhaft "stale" Host (`server/src/routes/report.rs:266-279`):
   Der Agent liest Paketnamen ohne Architektur; bei Multiarch kommt ein Name zweimal, `ON CONFLICT DO UPDATE` bricht
   dann ab. Nur mit `include_packages=true`. Am Code hergeleitet (Einfügebefehl vom Dirigenten nachgelesen), nicht
   ausgeführt.
3. Hintergrund-Tasks ohne Aufsicht (`server/src/worker.rs:13-14`, `main.rs:153-161`, `cve/refresh.rs:674`): Nach
   einem Panic oder gescheitertem Start sind Worker oder Feed-Scheduler weg, `/readyz` bleibt grün. Nicht nachgeprüft.

Phase 1, am Code: Zeilenklick fehlt in CVE-, Agents- und Quellen-Tabelle; Kachel-Grid nutzt feste Spaltenzahlen statt
`minmax(200px, 1fr)`; 44 rohe `<button>` in 14 Dateien neben der gemeinsamen Komponente, CVE-Werkzeugleiste 36 statt
32 px; in den Einstellungen steht noch sichtbar "Reports"; `docs/debian-source.md` nennt "2 von 25 Läufen" nicht.

## 5 Was du manuell tun musst

1. Speicher freigeben, dann den Lauf fortsetzen: Die UI-Sitzung hat zwei Stacks hinterlassen (Server 8080 mit Web
   3100/4100 und pw-ui-pg; Server 8081 mit Web 3200/4200 und pw-snap-pg). Beende, was du nicht brauchst, und schreibe
   "Mach bei der Zustandsdatei weiter". Offen sind dann Phase 1 (Tests und Restarbeiten), 2, 3, 4 und die
   ausführenden Teile von 5 und 6.
2. Branch `overnight/2026-11-12` selbst pushen, wenn gewünscht: `git -C /home/claude/patchwatch-night push -u origin
   overnight/2026-11-12`. Er liegt nur lokal und enthält nur `docs/overnight/`. Kein Neubau, keine Migration, kein
   Neustart, kein Schlüssel nötig. Das Tag `before-overnight-2026-11-12` ist gepusht.
3. Vor dem Push entscheiden, ob `docs/overnight/security.md` (offene Funde) ins private Repo soll.
4. Die mittleren Funde einplanen, zuerst die drei aus Abschnitt 4 und `refresh?wait=true`.
5. Aufräumen, wenn nicht fortgesetzt wird: `git worktree remove /home/claude/patchwatch-night` (ca. 620 MB
   node_modules). Die Stashes der UI-Sitzung (stash@{0}, stash@{1}) sind unberührt; stash@{0} ist ein überholter
   Zwischenstand der Hostliste und enthält auch eine frühe Fassung der STATE.md.

## 6 Nicht geprüft und warum

- Speicherregel (Swap über 50 %): clippy, cargo test, npm test, npm build, musl-Build, Docker-Builds, alle
  Playwright-Skripte (layout-check, a11y, e2e, responsive), Screenshots, Vergleich mit dem Design-Snapshot,
  Funktionstests, Migrationsläufe, Lasttest, Datenbank-Ausfall, Agent-Tests, install.sh-Prüfsummentest.
- `scripts/responsive-all.mjs` und der README-Abschnitt "Qualitätsprüfung" wurden nicht angelegt.
- Nie Teil dieses Laufs: echte Geräte, Safari, Firefox, echte Feed-Quellen.
- `cargo audit` ist nicht installiert. `npm audit`: 8 Meldungen moderate, alle in der Lint-Werkzeugkette.
- Git-Historie auf Geheimnisse durchsucht (139 Commits): nur Testwerte.
- Vom Modell abgelehnte Prüfpunkte: keine.

## 7 Umgebung

Eigener Server "claude" (kein frischer Klon), Linux 7.0, 4 CPU, 5,3 GB RAM, 2 GB Swap, 21 GB Platte frei. Fremde
Dienste laufen mit (lagerplatz, Redis). docker 29.9, node 22, npm 9, cargo/rustc 1.95 mit musl-Target, shellcheck,
systemd-analyze, Playwright und Chromium vorhanden; kein psql. Netz zu npm und crates-Index ok. Push erlaubt.
Gearbeitet wurde im Worktree `/home/claude/patchwatch-night`, damit die laufende Instanz auf Port 3100 (liest aus
`web/.next` des Hauptverzeichnisses) heil bleibt; `/home/claude/patchwatch` steht sauber auf dev. Im Repo gibt es
keine CLAUDE.md.

## 8 Agenten

| Modell | Anzahl | Aufgaben |
|---|---|---|
| Haiku | 4 | drei Prüfungen der Wartebedingung, Umgebungsprüfung |
| Sonnet | 3 | Modelltest, Phase 1 am Code, Phase 6 Dateiprüfung |
| Opus | 4 | Modelltest, Sicherheit Teil 1 und 2, Phase 5 Code-Review |
| Fable (Dirigent) | - | Plan, Stichproben von vier Funden am Code, fmt, lint, typecheck, npm audit, Historiensuche, Berichte |

Keine Eskalationen. Zwei Agenten wurden vom Nutzungslimit unterbrochen; einer hatte seinen Befund schon geschrieben,
der andere wurde fortgesetzt. Alle Agenten haben nur gelesen und ihre Befunde außerhalb des Arbeitsbaums abgelegt.

## 9 Rückweg

`git checkout before-overnight-2026-11-12` (identisch mit dev 8cf3064; der Nachtbranch fügt nur Dokumente hinzu).
