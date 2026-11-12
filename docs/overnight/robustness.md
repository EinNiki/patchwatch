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
