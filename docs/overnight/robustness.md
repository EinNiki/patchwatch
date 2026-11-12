# Nachtlauf 2026-11-12: Robustheit

Stack: Wegwerf-Datenbank `pw-night-pg`, Server :8091 (Debug-Build), Mock-Feeds :8190. Keine Anfragen an echte Feed-Quellen.

## Flackernder Test e2e-dialogs

`scripts/e2e-dialogs.mjs` scheiterte bei „390/dark: Fokus kehrt zur Schaltfläche zurück“ (vor der Änderung 4 von 5 Läufen rot).
Ursache: **Race im Test, kein Fehler im Web.** `useModal` gibt den Fokus im `close`-Ereignis des Dialogs zurück; der Browser löst es
als eigene Aufgabe nach `dialog.close()` aus. `waitFor({ state: "hidden" })` ist schon erfüllt, bevor es läuft. Mit einer Wartezeit
von 1,5 s war der Fokus in allen Läufen korrekt. Der Test pollt jetzt auf `document.activeElement` (2 s Timeout, schlägt bei
fehlender Rückgabe weiterhin fehl); dieselbe Stelle beim Escape-Pfad ebenso. Ergebnis: 10 Läufe in Folge grün.

## Eingaben

`scripts/fuzz-inputs.mjs` (nur fetch): meldet sich einmal an und schickt an alle Routen aus `server/src/routes/mod.rs` ungewöhnliche Werte:
leer, 10.000 Zeichen, Unicode (café, 日本語, Emoji, Kombinationszeichen, RTL-Override), Steuerzeichen, NUL (URL-kodiert und `\u0000`),
negative, 0, 2^31, 2^63, 1e308, Nicht-Zahlen, falsche JSON-Typen. Abgedeckt: Query-Parameter aller lesenden Routen (q, releases,
distro, affects, sort, dir, limit, offset, status, group, kind, level_min, cves, hosts, …) einzeln, doppelt und kombiniert, alle
Pfad-IDs, JSON-Bodys der schreibenden Routen (Hosts, Watchlist, Einstellungen, OIDC, Kanäle, Quellen, Passwort, Avatar, Anmeldung)
und ohne Anmeldung `/report` und `/agent/checkin` mit ungültigen Tokens und kaputten Bodys (auch 5 MiB). Erwartung je Anfrage: nie 5xx,
unter 5 s; danach `/readyz` erreichbar. Schreibende Aufrufe nur mit Werten, die abgelehnt werden sollen, bestehende Host-IDs und
Quellen werden ausgespart.

Ergebnis (Lauf nach dem Fix): 3.659 Anfragen (2xx 512, 4xx 3.144), **keine 5xx**, langsamste Antwort 71 ms, `/readyz` danach 200.
Das Skript braucht rund 7 Minuten, weil das allgemeine Limit (600 Anfragen/min je IP) abgewartet wird; 429 zählt als 4xx.
11 „Hinweise“ sind keine Fehler: wenige Werte sind gültig und wurden angenommen (Notiz an `CVE-2099-0001`, ein Intervall, per `null`
angelegte Quellen); das Skript räumt Watchlist-Eintrag und Quellen auf, der Seed wird mit `down && up` wiederhergestellt.

| Fehlerklasse | Beleg | Behebung | Test |
| --- | --- | --- | --- |
| Report mit NUL in einem unbekannten Feld (jsonb `reports.raw`) lieferte 500 (M3); zudem beliebig große Zusatzfelder bis 4 MiB | Das Skript erreicht das nicht (braucht ein gültiges Host-Token, es legt nichts an); gefunden über die Liste der Eingabewege und per Test bestätigt (500) | `report.rs`: NUL in Texten und Schlüsseln und mehr als 64 KiB Rest ohne Paketliste ergeben 400, nichts wird gespeichert | `api.rs` `nul_and_oversize_unknown_report_fields_are_400` (vor dem Fix rot: 500) |

Die übrigen NUL-Pfade (N1: Anmeldung, Watchlist-Notiz, Intervall-Schlüssel, OIDC) waren schon behoben und sind durch Tests und das Skript gedeckt.
**Nicht geprüft:** Reports mit gültigem Host-Token im Skript (nur der Rust-Test), Avatar-Upload mit gültigem Bild,
ein Rate-Limit je Host für Reports (M3 Teil 2, nicht Teil dieses Auftrags).

## Lasttest

`scripts/load-test.mjs` (nur fetch): je Route 10 Runden mit 50 gleichzeitigen Anfragen, Median/p95/Maximum, RSS des Servers aus
`/proc/<pid>/status`. Das API-Limit von 600 Anfragen/min je IP würde die Messung verfälschen; der Wegwerf-Server lief deshalb mit
`PATCHWATCH_TRUST_PROXY=true`, das Skript schickt je Anfrage eine eigene `X-Forwarded-For`-Adresse.

Daten: `scripts/mock-feeds.mjs 8190 --demo-load=3000` (oder `MOCK_DEMO_LOAD=3000`) hängt 3.000 erzeugte, als „[Demo-Last]“ markierte
CVEs (`CVE-2031-NNNNN`) an Debian `linux`/trixie an (nicht im Repo, ohne die Option unverändert), ein Abruf gegen den Mock brachte
**3.011 CVE-Einträge je Trixie-Host** (db-01, db-02), die übrigen Hosts behielten 2 bis 11. Mischung: rund 60 % behoben, 25 % offen,
15 % erst in neuerer Version behoben.

Einschränkungen: Server als **Debug-Build** (unoptimiert, also pessimistisch), Postgres-Pool 10, Client und Server auf derselben
Maschine (5 GB RAM, 2 Kerne). Einzelanfragen ohne Last: `/cves?affects=all&limit=500` 70 ms, `/hosts/{id}/cves?limit=1000` 107 ms.

| Route | Anfragen | Median (ms) | p95 (ms) | Maximum (ms) |
|---|---:|---:|---:|---:|
| GET /hosts | 500 | 74 | 161 | 175 |
| GET /cves (Standard) | 500 | 294 | 367 | 429 |
| GET /cves?affects=all | 500 | 281 | 342 | 361 |
| GET /cves?affects=all&limit=500 | 500 | 907 | **1.840** | 2.129 |
| GET /hosts/{id} (3.009 CVE-Einträge) | 500 | 48 | 60 | 61 |
| GET /hosts/{id}/cves (Standard, 100) | 500 | 420 | 468 | 487 |
| GET /hosts/{id}/cves?limit=1000 | 500 | 1.205 | **1.519** | 1.694 |
| GET /feeds | 500 | 91 | 102 | 104 |

Server-RSS vorher/nachher: 61 MB / 165 MB (Spitze unter Last, danach kein Wachstum gemessen).

Bewertung: Alle Standardrouten liegen mit 50 gleichzeitigen Anfragen unter 0,5 s p95. Über 1 s liegen nur die Seiten mit dem
Höchstlimit (500 CVEs bzw. 1000 Einträge, 350 bis 540 KB je Antwort). Die Web-Oberfläche fragt höchstens `limit=200` ab
(`HostCves.tsx`, Vorabruf) bzw. den Standard 100. Nichts umgebaut (Vorgabe: melden). Möglicher Anschluss: Release-Build messen, bevor man
Abfragen anfasst; die Last entsteht beim Warten auf die 10 Datenbankverbindungen und beim Serialisieren der großen Antworten.
**Nicht geprüft:** Release-Build, Datenbank auf anderer Maschine, 3.000 CVEs bei mehr als zwei Hosts gleichzeitig.

## Docker

`docker compose --env-file <Kopie von .env.example mit zufälligem POSTGRES_PASSWORD> config -q`: Exit 0 (Kopie danach gelöscht).
Vor jedem Build `free -m` (4,1 GB verfügbar) und `df -h` (20 GB frei, über der Schwelle von 8 GB).

| Image | Befehl | Dauer | Größe | Benutzer |
|---|---|---:|---:|---|
| `pw-night-server:test` | `docker build -f server/Dockerfile .` (Rust release, Basis debian:trixie-slim) | 3 min 07 s | 135 MB | uid 10001 `patchwatch` |
| `pw-night-web:test` | `docker build -f web/Dockerfile .` (npm ci, next build, node:22-slim) | 1 min 23 s | 424 MB | uid 10001 `patchwatch` |

Beide Builds liefen ohne Fehler, kein Fix nötig. `docker inspect` zeigt `User=10001`, `docker run --rm --entrypoint id` bestätigt
Nicht-root (uid 10001). Kein `compose up`. Die Test-Images wurden mit `docker rmi` wieder entfernt, kein prune.

## Migrationen

Gegen die zweite Wegwerf-Datenbank `pw-night-pg2` (127.0.0.1:55441), Server :8092, eigener Mock :8191. Für den Test mit zwei
gleichzeitigen Servern lief der zweite kurz auf 127.0.0.1:8192 (eigener 81xx-Bereich; 8092 ist mit dem ersten belegt). Alles danach
entfernt.

| Fall | Ergebnis |
| --- | --- |
| Leere Datenbank, erster Start | 20 Migrationen (0001–0020) in Reihenfolge (`installed_on` sortiert wie `version`), alle `success`, zusammen 0,2 s; `/readyz` nach 2 s, ein Admin |
| Zweiter Start | No-op: Prüfsummen und `installed_on` unverändert (Hash über alle Zeilen gleich), keine Fehler im Log, weiter ein Admin |
| Start mit Seed-Daten (7 Hosts, 11 CVEs, 57 Host-CVE-Zeilen, nach `dev-seed.py` und Abruf) | Zahlen und Migrationen unverändert, keine Fehler |
| Zwei Server gleichzeitig gegen dieselbe leere Datenbank | Migrationen genau einmal (Advisory Lock), eine Admin-Zeile, keine Fehler. **Aber** beide gaben ein Start-Passwort aus, gültig war nur das zweite (Login 401/200). Behoben in `3d02559` (Anlegen ohne Überschreiben); danach gibt nur ein Prozess ein Passwort aus (Login 200), der andere keines |
| Datenbank startet 20 s nach dem Server (N5) | **Bestätigt:** Exit 1 nach 5,0 s („pool timed out while waiting for an open connection“). **Behoben** in `a4befe2`: Wiederholung mit Backoff 1 s bis 5 s, höchstens 60 s, jeder Versuch geloggt; im Nachtest 3 Versuche, bereit nach 22,3 s. Andere Fehler (falsches Passwort, ungültige Adresse) brechen weiter sofort ab; nach 60 s endet der Server wie vorher (Compose `restart` fängt das ab) |
| Absturz mit hängendem Lauf | Mock `POST /__mode {"mode":"hang"}`, Abruf im Hintergrund: Debian-Lauf `running`/`connect`. Server mit SIGKILL beendet, neu gestartet: Lauf `interrupted` („Der Lauf wurde unterbrochen …“), neuer Abruf sofort möglich (200, Debian `not_modified`, Ubuntu `updated`) |
| Job „in Arbeit“ eines beendeten Prozesses | Nachgestellt (Job mit `locked_at = now()`, `attempts = 1`, als hätte ihn der getötete Prozess beansprucht): nach Ablauf der Lease von 5 min erledigt (gesperrt 16:23:06, erledigt 16:28:20, `attempts` 2) |

N6 (zwei Server stören sich bei Feed-Läufen: der zweite markiert die laufenden des ersten als unterbrochen) ist **nicht geprüft** und
bleibt offen; das Design setzt weiter genau einen Server je Datenbank voraus.

## Ausfall

`scripts/e2e-outage.mjs` gegen den Seed-Stack (:8091, :3300): `pw-night-pg` 30 s gestoppt (`docker stop`/`docker start`, nur dieser
Container), ein Playwright-Lauf. Vor den Fixes 10 FAIL (frühe Fassung des Skripts, ohne die Render-Fehler-Prüfung), mit neuem
Server und altem Web 9 FAIL (Render-Fehler, UI, Umleitung), nach allen Fixes **29 von 29 OK** (mit Seitentitel der Fehlerseiten).

| Hypothese | Befund vorher | Ergebnis |
| --- | --- | --- |
| N2: API im Ausfall 500 statt 503 | `GET /hosts` 500 „interner Fehler“ nach 5,0 s, Login 500, `/readyz` 503 | **Behoben** in `fa6a75a`: 503 „Die Datenbank ist gerade nicht erreichbar. Bitte in einigen Sekunden erneut versuchen.“, `code: db_unavailable`, `Retry-After: 5`, auch Login und Anmeldeprüfung; keine internen Details; Rust-Test `database_outage_is_503_without_details` (vorher rot: 500) |
| N3: jeder Fehler von `/auth/me` führt zur Anmeldung | Neuladen im Ausfall landete auf `/login` | **Behoben** in `3dda8ab`: nur 401 leitet um, sonst Fehlerseite „Anmeldung kann gerade nicht geprüft werden“ mit „Erneut versuchen“; bleibt im Ausfall im Fehlerzustand, lädt nach der Erholung die Host-Liste ohne neue Anmeldung; Test `web/tests/session.test.mts` |
| N4: keine `error.tsx`/`global-error.tsx` | Render-Fehler (nachgestellte unerwartete API-Antwort) ergab die englische Next-Seite „This page couldn’t load“ | **Behoben** in `1ad84bc`: Fehler einer Seite (CVE-Liste) im App-Rahmen mit Navigation, Fehler im Rahmen (Host-Liste der Seitenleiste) als ganze Seite, beide deutsch mit „Erneut versuchen“; Seitentitel der ganzseitigen Fehlerseite in `81ba2a9` |

Erholung ohne Neustart (gleiche PID): `/readyz` 200 0,5 bis 0,6 s nach `docker start`, die alte Sitzung gilt, 7 Hosts und 9 CVEs vorher
wie nachher, Live-Anzeige wieder „Live“. LISTEN/NOTIFY: eine Report-Anforderung kommt vor und nach dem Ausfall per WebSocket an; der
WebSocket selbst blieb offen (er braucht keine Datenbank), nach der Neuverbindung des Live-Listeners kam `resync`. Log während 30 s
Ausfall: 4 Warnungen des Live-Listeners, 3 fehlgeschlagene Worker-Durchläufe, die 503 je eine Zeile (tower-http loggt 5xx als ERROR),
keine Flut, CPU danach 0 %.

Worker (gegen `pw-night-pg2`, Job mit `pg_notify`): vor dem Ausfall nach 76 ms erledigt, danach nach 351 ms und 80 ms, also über
LISTEN und nicht erst über die 15-s-Abfrage. `pg_terminate_backend` auf beide LISTEN-Verbindungen (offene Frage „ECONNRESET“ aus
Phase 5): beide verbinden neu, Jobs nach 72 und 99 ms, keine Schleife, CPU 0 %.

M4 (Hintergrund-Tasks nach Fehlstart): Die Erholung **im Betrieb** ist bestätigt (Worker, Live-Listener). Ein Fehlstart des Listeners
direkt nach den Migrationen und Panics in den Hintergrund-Tasks wurden **nicht nachgestellt**; M4 bleibt offen.
Hinweis: Im Ausfall wartet jede Anfrage bis zum `acquire_timeout` (5 s), bevor 503 kommt; nicht geändert.

Stichprobe der drei neuen Fehlerzustände (Anmeldeprüfung 503, Render-Fehler der Seite und des Rahmens) bei 320, 390 und 1440 px,
hell und dunkel, Schrift 100 % und 200 %: kein waagrechter Überlauf, axe ohne serious/critical (36 Prüfungen, nach dem Titel-Fix;
davor fehlte der Seitentitel der ganzseitigen Fehlerseite). `responsive-all` nicht gelaufen: bestehende Seitenlayouts unverändert.

## Zeit

| Prüfung | Test | Ergebnis |
| --- | --- | --- |
| Tageszusammenfassung am 29.03. und 25.10.2026 (Europe/Berlin), 08:00 und 02:30 | `worker::tests::daily_summary_once_on_*` (Minuten-Scheduler über den Kalendertag simuliert) | In Ordnung: je Tag genau ein Schlüssel; 02:30 im März um 03:00 (01:00 UTC), im Oktober beim ersten Vorkommen (00:30 UTC). Verhalten unverändert, nur als `daily_summary_key` herausgelöst (`e8c955c`) |
| N7: tägliche Report-Anforderung am Umstellungstag | `schedule::tests::daily_fires_after_nonexistent_dst_time` (vorher rot: letzter Lauf blieb der 28.03.) | **Bestätigt, behoben** in `eae2a7f`: Uhrzeit in der Lücke löst zum ersten gültigen Zeitpunkt danach aus (03:00), genau einmal; Oktober einmal beim ersten Vorkommen (`daily_runs_once_on_repeated_dst_hour`) |
| Relative Zeit über den Wechsel | `web/tests/format.test.mts` (`0c6bd98`) | In Ordnung: „vor n Tagen“ zählt Berliner Kalendertage (26 h am 25-Stunden-Tag = „vorgestern“, 24,5 h am selben Tag = „heute“) |
| Stale-Grenze 26 h | `status::tests::stale_boundary_is_strict` | In Ordnung: genau 26 h nicht stale, 26 h + 1 s stale; über den Oktoberwechsel zählt die echte Zeitspanne. SQL in `mark_stale_hosts` ist ebenfalls strikt (`<`, am Code) |
| Agent-Uhr eine Stunde falsch | `api.rs::wrong_agent_clock_does_not_matter` (+1 h, −1 h, −27 h) | In Ordnung: „Zuletzt gemeldet“ ist die Serverzeit beim Empfang, Host nicht stale |
| N8: Bootzeit wandert | `format.test.mts` „Bootzeit nach Neustart …“ | **Bestätigt (Mechanismus), nicht behoben:** die Bootzeit liegt je Report um die Zeit zwischen Lesen der Uptime und Empfang zu spät, nicht kumulativ; die Minutenanzeige springt höchstens an einer Minutengrenze um eine Minute, nach einem Neustart gilt sofort der neue Wert. Mit echtem Agent nicht gemessen |
