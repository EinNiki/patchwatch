# Nachtlauf 2026-11-12: Bericht

## 1 Gesamtstatus: GELB

Zwei Serverfehler sind mit Test behoben, alle ausgeführten Prüfungen sind grün, aber große Teile des Plans sind
nicht gelaufen: Bis 04:43 UTC blockierten die Speicherregel (Swap 53 bis 58 %, belegt durch Reste der UI-Sitzung)
und ein Nutzungslimit (00:19 bis 04:10 UTC) alle Builds, Tests und Browserläufe. Nach deiner Freigabe habe ich die
Reste der UI-Sitzung beendet; danach blieb bis zur Zeitgrenze (05:30 UTC) eine knappe Stunde.

| Phase | Status |
|---|---|
| Warten auf UI-Sitzung | fertig (23:59 UTC, sauber, alles auf origin/dev 8cf3064) |
| 0 Sicherung, Branch | fertig |
| 1 UI-Restarbeiten | geprüft, nichts gebaut: am Code (phase1.md) und mit 11 E2E-Skripten grün; Restarbeiten offen |
| 2 Qualitätsschranken | grün außer Docker: fmt, clippy, cargo test (335), npm lint, typecheck, test (100), build, musl-Build, install_test (58). Docker-Builds nicht gelaufen |
| 3 Responsiv | nicht gelaufen (nur layout-check ohne Host-Seiten: 104 Prüfungen, 0 Verstöße) |
| 4 Funktionstests | nicht gelaufen |
| 5 Daten, Zeit, Robustheit | Code-Review (phase5.md); zwei Funde mit Test behoben; Läufe (Migration, Last, Ausfall) nicht gelaufen |
| 6 Agent, Deployment | Dateiprüfung (phase6.md), musl-Build und Agent-Tests grün; Docker nicht gelaufen |
| 7 Sicherheit | fertig, nur lesend (security.md) |
| 8 Push | siehe STATE.md (Stand des Pushs) |

## 2 Zuerst lesen

Keine kritischen Funde, keine roten Tests. Mittlere Sicherheitsfunde, alle offen (nur gemeldet, wie vereinbart):

- **NVD-Schlüssel folgt einer geänderten Spiegel-URL** (`server/src/routes/feeds.rs:669-676`): Die Adresse einer
  Quelle lässt sich ändern, ohne dass das gespeicherte Geheimnis verworfen wird, auch auf `http://`. Braucht eine
  Admin-Sitzung. Altbestand vor dem Audit-Commit.
- **`POST /feeds/refresh?wait=true` umgeht Mindestabstand, Backoff-Bestätigung und Lauf-Protokoll**
  (`feeds.rs:906, 968-990`). Vom Dirigenten nachgelesen.
- **`install.sh` ist nicht signiert**; der in der Oberfläche gezeigte Befehl führt es mit sudo aus
  (`web/src/lib/agentCommands.ts:5`). Nicht nachgeprüft.
- Hoch in Phase 6, aber bekannt und gewollt: `PW_PUBKEY` in `install.sh:97` ist noch Platzhalter.

Diese Prüfung war keine Vollprüfung und ersetzt den unabhängigen Opus-Audit in frischer Sitzung nicht.

Der Branch enthält Code: zwei Fixes in `server/src/routes/` (report.rs, auth.rs, cves.rs, settings.rs, oidc.rs,
mod.rs), Tests in `server/tests/api.rs` und eine Korrektur in `scripts/e2e-rowlink.mjs`.

## 3 Zahlen je Phase

| Phase | gefunden | behoben | offen |
|---|---|---|---|
| 1 | 4 Punkte nur teilweise umgesetzt, 4 Auffälligkeiten, 1 Fehler in einem Testskript | 1 (Testskript) | 8 |
| 2 | 0 | 0 | 0 |
| 3, 4 | nicht geprüft | - | - |
| 5 | 13 (0 hoch, 4 mittel, 9 niedrig) | 2 (M1 doppelte Paketnamen, N1 NUL-Zeichen) | 11 |
| 6 | 20 (1 hoch, 4 mittel, 9 niedrig, 6 Hinweise) | 0 | 20 |
| 7 | 21 (0 kritisch, 0 hoch, 3 mittel, 18 niedrig) | 0 | 21 |

Behoben, je ein Commit mit Test, der ohne den Fix fehlschlägt:
- `53f1304` fix(server): Doppelte Paketnamen im Report (Multiarch) endeten mit 500, der Host wäre "stale" geworden.
  Der Server führt gleiche Namen jetzt zusammen (höchste Version). Die CVE-Bewertung nutzt die Paketliste nicht.
- `1870417` fix(server): NUL-Zeichen in Login-Benutzername, Watchlist-Notiz, Feed-Intervallen und OIDC-Einstellungen
  ergaben 500 (Login ohne Anmeldung erreichbar), jetzt 400. Der Login-Versuch wird weiter vom Rate-Limit gezählt.
- `3a97664` test(e2e): `e2e-rowlink` nahm die erste API-Zeile statt der ersten Listenzeile.

## 4 Die schwersten drei offenen Funde

1. NVD-Schlüssel geht an eine geänderte Spiegel-URL (security.md M1).
2. Hintergrund-Tasks ohne Aufsicht (`server/src/worker.rs:13-14`, `main.rs:153-161`, `cve/refresh.rs:674`): Nach
   einem Panic oder gescheitertem Start sind Worker oder Feed-Scheduler weg, `/readyz` bleibt grün. Am Code
   hergeleitet, nicht nachgeprüft.
3. Der Agent wiederholt einen fehlgeschlagenen Tagesreport nicht (`agent/src/main.rs:121`): Ein kurzer Serverausfall
   mittags kann nach 26 Stunden alle Hosts "stale" machen. Am Code hergeleitet, nicht nachgeprüft.

Beobachtung ohne Untersuchung: Die beiden Debug-Server der UI-Sitzung wuchsen im Leerlauf in viereinhalb Stunden von
ca. 1,1 auf 1,3 bis 1,6 GB RSS. Ein frischer Server ohne Feed-Daten belegt 50 MB. Mögliches Speicherleck oder
Feed-Daten im Speicher; bitte prüfen.

Phase 1, offen: Zeilenklick fehlt in CVE-, Agents- und Quellen-Tabelle; Kachel-Grid nutzt feste Spaltenzahlen statt
`minmax(200px, 1fr)`; 44 rohe `<button>` in 14 Dateien neben der gemeinsamen Komponente, CVE-Werkzeugleiste 36 statt
32 px; in den Einstellungen steht sichtbar "Reports"; `docs/debian-source.md` nennt "2 von 25 Läufen" nicht.

## 5 Was du manuell tun musst

1. Branch `overnight/2026-11-12` prüfen und nach dev mergen. Danach den Server neu bauen und neu starten (zwei
   Fixes). Keine Migration, kein neuer Schlüssel. Web ist unverändert.
2. Die Instanz der UI-Sitzung auf Port 3100 läuft nicht mehr: Ich habe ihre Prozesse (Server 8080 und 8081, Web
   3100/4100 und 3200/4200) beendet und die Container `pw-ui-pg` und `pw-snap-pg` gestoppt (nicht gelöscht, Daten
   erhalten). Neu starten: `docker start pw-ui-pg`, dann Server und Web wie in der README.
3. Fortsetzen mit "Mach bei der Zustandsdatei weiter": offen sind Phase 1 (Restarbeiten), 3, 4, die Läufe aus 5,
   Docker-Builds und ein Seed mit CVE-Daten aus Mock-Feeds (ohne ihn bleiben Host-Seiten und CVE-Liste leer).
4. Entscheiden, ob `docs/overnight/security.md` (offene Funde) im privaten Repo bleiben soll.
5. Aufräumen, wenn nicht fortgesetzt wird: `git worktree remove /home/claude/patchwatch-night` (ca. 1 GB mit
   node_modules und .next). Die Stashes der UI-Sitzung sind unberührt; stash@{0} ist ein überholter Zwischenstand
   der Hostliste.

## 6 Nicht geprüft und warum

- Zeit (Speicherregel und Nutzungslimit bis 04:43 UTC): Phase 3 (alle Breiten, Zoom, dunkel, Vergleich mit dem
  Design-Snapshot), Phase 4, Migrationsläufe, Lasttest, Datenbank-Ausfall, Docker-Builds, `scripts/
  responsive-all.mjs` und der README-Abschnitt "Qualitätsprüfung" (beide nicht angelegt).
- Fehlende CVE-Daten im Seed-Stack (Feeds bewusst stillgelegt, kein Mock-Feed): `layout-check` und `a11y` konnten die
  Host-Seiten nicht vollständig prüfen. `a11y` lief nur als Kopie außerhalb des Repos ohne den Klick auf die
  Gefixt-Gruppe: keine axe-Verstöße. `e2e-feedruns` und die übrigen E2E-Skripte liefen nicht.
- Vom Dirigenten angesehen: nur Hosts bei 1440 px und Agents bei 390 px (hell), beide unauffällig.
- Nie Teil dieses Laufs: echte Geräte, Safari, Firefox, echte Feed-Quellen.
- `cargo audit` ist nicht installiert. `npm audit`: 8 Meldungen moderate, alle in der Lint-Werkzeugkette.
- Git-Historie auf Geheimnisse durchsucht (139 Commits): nur Testwerte.
- Vom Modell abgelehnte Prüfpunkte: keine.

## 7 Umgebung

Eigener Server "claude" (kein frischer Klon), Linux 7.0, 4 CPU, 5,3 GB RAM, 2 GB Swap, 21 GB Platte frei. Fremde
Dienste laufen mit (lagerplatz, Redis; nicht angefasst). docker 29.9, node 22, npm 9, cargo/rustc 1.95 mit
musl-Target, shellcheck, systemd-analyze, Playwright und Chromium vorhanden; kein psql. Netz zu npm und
crates-Index ok. Gearbeitet wurde im Worktree `/home/claude/patchwatch-night`; `/home/claude/patchwatch` steht
sauber auf dev (nur der Build-Cache `target/` wurde mitbenutzt). Im Repo gibt es keine CLAUDE.md.

## 8 Agenten

| Modell | Anzahl | Aufgaben |
|---|---|---|
| Haiku | 4 | drei Prüfungen der Wartebedingung, Umgebungsprüfung |
| Sonnet | 7 | Modelltest, Phase 1 am Code, Phase 6 Dateiprüfung, Phase 2 Rust und Agent, Seed-Stack mit Browser-Tests, Fix Paketnamen, Fix NUL-Zeichen |
| Opus | 4 | Modelltest, Sicherheit Teil 1 und 2, Phase 5 Code-Review |
| Fable (Dirigent) | - | Plan, Stichproben am Code, Diffs der Fixes gelesen, alle Schranken vor dem Push selbst ausgeführt, Berichte |

Keine Eskalationen; Opus und Fable mussten keinen Fehler lösen. Zwei Agenten wurden vom Nutzungslimit unterbrochen.

## 9 Rückweg

`git checkout before-overnight-2026-11-12` (identisch mit dev 8cf3064).
