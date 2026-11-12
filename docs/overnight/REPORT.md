# Nachtlauf 2026-11-12: Bericht

## 1 Gesamtstatus: GRÜN mit offenen Funden

Alle Phasen sind gelaufen, und alle Prüfungen sind in der Abschlussprüfung des Dirigenten grün (12.11., 17:12 bis
18:35 UTC, alles nacheinander selbst ausgeführt). Der Lauf hat weit länger gedauert als geplant: Bis 04:43 UTC
blockierten die Speicherregel und ein Nutzungslimit fast alles; danach wurde er auf deine Anweisung fortgesetzt
("alles selber", später "bis alle Tests grün sind") und dreimal vom Nutzungslimit unterbrochen. Die Zeitgrenzen des
ursprünglichen Auftrags (7 Stunden, Bericht bis 07:00 UTC) wurden damit bewusst überschritten.

| Phase | Status |
|---|---|
| Warten auf UI-Sitzung | fertig (23:59 UTC, sauber, alles auf origin/dev 8cf3064) |
| 0 Sicherung, Branch | fertig |
| 1 UI-Restarbeiten | fertig: 5 Commits mit Browser-Tests (phase1.md nennt den Stand davor) |
| 2 Qualitätsschranken | fertig, grün (auch Docker-Builds) |
| 3 Responsiv | fertig: `responsive-all.mjs` 638 Zustände x Varianten, 0 Verstöße (responsive.md) |
| 4 Funktionstests | fertig: `e2e-functional.mjs` 189 OK, 1 übersprungen; 15 vorhandene Skripte grün (functional.md) |
| 5 Daten, Zeit, Robustheit | fertig: Fuzzing, Lasttest, Migrationen, Ausfall, Zeit (robustness.md, phase5.md) |
| 6 Agent, Deployment | fertig: Dateiprüfung (phase6.md), musl-Build, Agent-Tests, Docker-Builds |
| 7 Sicherheit | fertig, nur lesend (security.md) |
| 8 Aufräumen, Push | aufgeräumt; Stand des Pushs siehe STATE.md |

## 2 Zuerst lesen

Keine kritischen Funde, keine roten Tests. Drei mittlere Sicherheitsfunde sind offen (nur gemeldet, wie vereinbart):

- **NVD-Schlüssel folgt einer geänderten Spiegel-URL** (`server/src/routes/feeds.rs`, Update der Quelle): Die Adresse
  einer Quelle lässt sich ändern, ohne dass das gespeicherte Geheimnis verworfen wird, auch auf `http://`. Braucht
  eine Admin-Sitzung. Altbestand vor dem Audit-Commit.
- **`POST /feeds/refresh?wait=true` umgeht Mindestabstand, Backoff-Bestätigung und Lauf-Protokoll.** Vom Dirigenten
  nachgelesen. Der neue Seed-Stack (`scripts/dev-stack.sh`) nutzt genau diesen Aufruf für seinen einen Abruf gegen
  den lokalen Mock; wird der Wartepfad entfernt, muss das Skript angepasst werden.
- **`install.sh` ist nicht signiert**; der in der Oberfläche gezeigte Befehl führt es mit sudo aus. Nicht nachgeprüft.
- Hoch in Phase 6, aber bekannt und gewollt: `PW_PUBKEY` in `install.sh` ist noch Platzhalter.

Die Sicherheitsprüfung war keine Vollprüfung und ersetzt den unabhängigen Opus-Audit in frischer Sitzung nicht. Die
Zeilennummern in security.md, phase5.md und phase6.md beziehen sich auf den Stand vor den Fixes dieser Nacht.

Der Branch ändert Verhalten. Das solltest du vor dem Mergen ansehen:
- Hosts-Tabelle: Zwischen 1024 und 1279 px entfällt jetzt die Spalte "Updates" (sie passte dort nicht, der
  Status-Chip wurde abgeschnitten).
- Agents-Tabelle: Ab 1024 px sind alle sieben Spalten sichtbar, die Zeilen brechen dafür stärker um.
- CVE-Tabelle: Die ganze Zeile ist klickbar. Agents- und Quellen-Tabelle bewusst nicht (kein Detailziel).
- CVE-Werkzeugleiste: 32 statt 36 px (wie in web/DESIGN.md).
- Bei großer Schrift (200 %) stapeln Tabellen, und die Spalte "Host-Details" rückt unter den Inhalt.
- Server: 503 statt 500 bei Datenbank-Ausfall, Start wartet bis zu 60 s auf die Datenbank, 400 statt 500 bei
  NUL-Zeichen, doppelte Paketnamen im Report werden zusammengeführt.
- Web: Nur 401 führt zur Anmeldeseite; sonst erscheint ein Fehlerzustand mit "Erneut versuchen". Neue Fehlerseiten.

## 3 Zahlen je Phase

| Phase | gefunden | behoben | offen |
|---|---|---|---|
| 1 | 4 Punkte nur teilweise umgesetzt, 4 Auffälligkeiten | 5 Commits (Zeilenklick, Kacheln, Begriffe, Agents-Spalten, Knöpfe) | Debian-Dokument ohne "2 von 25"; rohe Knöpfe außerhalb gleichrangiger Aktionszeilen |
| 2 | 1 flackernder Agent-Test (EPIPE im Testhelfer, 1 von 6 Läufen) | 1 | 0 |
| 3 | 287 Verstöße im ersten Lauf | alle in den 22 Varianten (14 Commits) | Schrift 125 % und 150 % bei 1280 px läuft weiter über (nicht Teil der Varianten) |
| 4 | 0 Produktfehler; 5 veraltete Skripte, 1 flackernder Test | alle | Zustellung an Kanäle und öffentliche Quellen-Adresse nur über Rust-Tests |
| 5 | 13 aus dem Code-Review, 1 beim Fuzzing | 9 (siehe unten) | M2, M4, N6 Feed-Teil, N8, N9, Rate-Limit je Host für Reports |
| 6 | 20 (1 hoch, 4 mittel, 9 niedrig, 6 Hinweise) | 1 (README-Abschnitt "Qualitätsprüfung") | 19 |
| 7 | 21 (0 kritisch, 0 hoch, 3 mittel, 18 niedrig) | 0 (eine Auffälligkeit daraus, NUL in der Watchlist-Notiz, ist behoben) | 21 |

Behobene Serverfehler, je mit Test, der ohne den Fix fehlschlägt:
- `53f1304` doppelte Paketnamen im Report (Multiarch) ergaben 500, der Host wäre "stale" geworden.
- `1870417`, `4605ec5` NUL-Zeichen in Login-Benutzername, Watchlist-Notiz, Feed-Intervallen, OIDC-Einstellungen und
  unbekannten Report-Feldern ergaben 500, jetzt 400; Zusatzfelder im Report sind auf 64 KiB begrenzt.
- `fa6a75a` Datenbank-Ausfall: 503 mit deutschem Text und `Retry-After` statt 500.
- `a4befe2` Start wartet bis zu 60 s auf die Datenbank statt nach 5 s abzubrechen.
- `3d02559` gleichzeitiger Erststart zweier Server legt den Admin nur einmal an.
- `eae2a7f` tägliche Report-Anforderung fällt am Tag der Sommerzeitumstellung nicht mehr aus.

Behobene Web-Fehler: Anmeldeprüfung leitet nur bei 401 um (`3dda8ab`), Fehlerseiten bei Render-Fehlern (`1ad84bc`,
`81ba2a9`), Popover und Menüs bleiben im Viewport, Trefferflächen 44 px in gestapelten Tabellen, Überläufe bei
schmalen Breiten und großer Schrift (Liste in responsive.md).

Neue Prüfskripte (README, Abschnitt "Qualitätsprüfung"): `dev-stack.sh`, `mock-feeds.mjs`, `responsive-all.mjs`,
`snapshot-diff.mjs`, `e2e-functional.mjs`, `e2e-outage.mjs`, `fuzz-inputs.mjs`, `load-test.mjs`.

## 4 Die schwersten drei offenen Funde

1. NVD-Schlüssel geht an eine geänderte Spiegel-URL (security.md, M1).
2. Hintergrund-Tasks ohne Aufsicht (phase5.md, M4): Nach einem Panic oder gescheitertem Start sind Worker oder
   Feed-Scheduler weg, `/readyz` bleibt grün. Am Code hergeleitet, nicht nachgestellt.
3. Der Agent wiederholt einen fehlgeschlagenen Tagesreport nicht (phase5.md, M2): Ein kurzer Serverausfall mittags
   kann nach 26 Stunden alle Hosts "stale" machen. Am Code hergeleitet, nicht nachgestellt.

Weitere Beobachtungen:
- Lasttest (Debug-Build, rund 3.000 CVEs je Host, 50 gleichzeitig): p95 unter 0,5 s auf allen Standardrouten. Über
  1 s nur mit Höchstlimit: `/cves?affects=all&limit=500` 1,84 s, `/hosts/{id}/cves?limit=1000` 1,52 s. Die
  Oberfläche fragt höchstens `limit=200` ab; nichts umgebaut.
- Die Debug-Server der UI-Sitzung (mit echten Feed-Daten) wuchsen im Leerlauf in viereinhalb Stunden von ca. 1,1 auf
  1,3 bis 1,6 GB RSS; der Seed-Server belegt 50 bis 165 MB. Nicht untersucht.
- Im Datenbank-Ausfall wartet jede Anfrage 5 s, bevor die 503 kommt.
- Falsches aktuelles Passwort beim Passwortwechsel liefert 403; eine Zeitüberschreitung beim Abruf erscheint als
  "Netzwerkfehler" ohne Hinweis auf das Zeitlimit.
- Chip-Höhe und die CVE-Einträge der Hostliste sind fest in px und wachsen bei großer Schrift nicht mit.

## 5 Was du manuell tun musst

1. Branch `overnight/2026-11-12` prüfen (besonders die Verhaltensänderungen aus Abschnitt 2) und nach dev mergen.
   Danach Server und Web neu bauen und neu starten. Keine Migration, kein neuer Schlüssel.
2. Die Instanz der UI-Sitzung auf Port 3100 läuft nicht mehr: Ihre Prozesse sind beendet, die Container `pw-ui-pg`
   und `pw-snap-pg` gestoppt (nicht gelöscht). Neu starten: `docker start pw-ui-pg`, dann Server und Web wie in der
   README.
3. Die offenen mittleren Funde einplanen (Abschnitt 2 und 4), danach den unabhängigen Audit.
4. Entscheiden, ob `docs/overnight/security.md` (offene Funde) im privaten Repo bleiben soll.
5. Aufräumen: `git worktree remove /home/claude/patchwatch-night` (ca. 1 GB). Die Stashes der UI-Sitzung sind
   unberührt; stash@{0} ist ein überholter Zwischenstand der Hostliste.

## 6 Nicht geprüft und warum

- Echte Geräte, Safari, Firefox, echte Feed-Quellen: nie Teil dieses Laufs. Alle Browser-Prüfungen liefen in Chromium.
- Zustellung von Benachrichtigungen und Annahme einer öffentlichen Quellen-Adresse: bräuchten Internet oder eine
  Abschwächung des SSRF-Schutzes; nur über Rust-Tests abgedeckt.
- Design-Snapshot: 20 von 28 Bildern weichen um mehr als 2 % ab. Der Agent ordnet das den gewollten Änderungen und
  anderen Seed-Daten zu und hat dafür vier Differenzbilder angesehen; die übrigen sind daraus abgeleitet.
- Vom Dirigenten angesehene Screenshots: Hosts (1440, 1024 px, Schrift 200 %), Agents (390, 1024 px), CVEs und
  Host-Detail (1440 px), alle hell. Nicht jede Seite bei 390, 1024, 1440 und 2560 px, wie der Auftrag es vorsah.
- Lasttest nur mit Debug-Build auf derselben Maschine. `docker compose up` und `caddy validate` nicht ausgeführt.
- `cargo audit` ist nicht installiert. `npm audit`: 8 Meldungen moderate, alle in der Lint-Werkzeugkette.
- `shellcheck` meldet für `install.sh` nur den Hinweis SC1091 (Stufe info); ab Stufe warning ist es sauber.
- Vom Modell abgelehnte Prüfpunkte: keine.

## 7 Umgebung

Eigener Server "claude" (kein frischer Klon), Linux 7.0, 4 CPU, 5,3 GB RAM, 2 GB Swap, 21 GB Platte frei. Fremde
Dienste laufen mit (lagerplatz, Redis; nicht angefasst). docker 29.9, node 22, npm 9, cargo/rustc 1.95 mit
musl-Target, shellcheck, systemd-analyze, Playwright und Chromium vorhanden; kein psql. Gearbeitet wurde im Worktree
`/home/claude/patchwatch-night`; `/home/claude/patchwatch` steht sauber auf dev (nur der Build-Cache `target/` wurde
mitbenutzt). Im Repo gibt es keine CLAUDE.md. Alle Tests liefen gegen einen Wegwerf-Stack mit Demo-Daten und lokalen
Mock-Feeds; es gab keine Anfrage an echte Feed-Quellen.

## 8 Agenten

| Modell | Anzahl | Aufgaben |
|---|---|---|
| Haiku | 4 | drei Prüfungen der Wartebedingung, Umgebungsprüfung |
| Sonnet | 12 | Modelltest, Phase 1 am Code, Phase 6 Dateiprüfung, Phase 2, Seed-Stack (zweimal), zwei Server-Fixes, UI-Restarbeiten, Phase 3, Phase 4, Flackertest mit Fuzzing, Lasttest und Docker |
| Opus | 6 | Modelltest, Sicherheit Teil 1 und 2, Phase 5 Code-Review, Eskalation Phase 3, Phase 5 Läufe |
| Fable (Dirigent) | - | Plan, Stichproben, Diffs der riskanten Fixes, Screenshots, zwei eigene Korrekturen, Abschlussprüfung, Berichte |

Eine Eskalation: Die letzten 33 Responsiv-Verstöße (Tabellen bei großer Schrift, Hosts bei 1024 px) hat Sonnet nicht
gelöst; Opus hat sie mit Container-Abfragen behoben. Der Dirigent hat selbst korrigiert: feste Pfade dieser Maschine
in `dev-stack.sh` und `e2e-functional.mjs`, und den flackernden Agent-Test. Vier Agenten wurden vom Nutzungslimit
unterbrochen und fortgesetzt.

## 9 Rückweg

`git checkout before-overnight-2026-11-12` (identisch mit dev 8cf3064).
