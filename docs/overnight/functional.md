# Nachtlauf 2026-11-12: Phase 4, Funktionstests Ende-zu-Ende

Stack: Wegwerf-Datenbank `pw-night-pg`, Server :8091, Web :3300, Mock-Feeds :8190 (nur lokale Mocks, keine echten Quellen).
Neues Skript: `scripts/e2e-functional.mjs` (API mit fetch, Browser nur für UI-Punkte, Exit 1 bei Fehlern). Der Mock bekam einen
Steuer-Endpunkt `POST /__mode` (Fehlermodi für den Debian-Feed). Der SSRF-Schutz und alle anderen Schutzmaßnahmen sind unverändert.

## A) Vorhandene Skripte

Ergebnis je Skript steht im Abschnitt „Endlauf“ unten. Fehlschläge beim ersten Lauf (alle Skript oder Umgebung, kein Produktfehler):

| Skript | Erstbefund | Einordnung | Behebung |
| --- | --- | --- | --- |
| e2e-avatar | Selektor und Größe 28 px | Skript veraltet: der Kreis im Fußbereich der Seitenleiste ist seit dem Raster der Navigation 20 px | Skript angepasst |
| e2e-watchlist | Schalter „nur Watchlist“ nicht gefunden | Skript veraltet: heute ein Knopf „Nur Watchlist“ (aria-pressed), keine Checkbox; zudem fest `pw-pg` und :3100 | Skript angepasst, `PW_PG_NAME` (Standard `pw-night-pg`), `PW_BASE` |
| e2e-feedruns | „Knopf gesperrt“ | Skript veraltet: der Abruf-Knopf ist im Lauf `aria-busy` (nicht `disabled`) und heißt „Debian: Abruf läuft“ | Skript angepasst |
| e2e-checkin | lief nicht | Skript veraltet: fest `pw-pg` (fremder Container, nie angefasst) und :3100; setzt Host `e2e-agent` voraus | Skript auf `PW_PG_NAME`/`PW_BASE`; Host und Konfiguration legt ein Hilfsskript im Scratchpad an |
| e2e-agents | Zeilenhöhe 86 px bei web-01 | Umgebung: web-01 trug eine offene, unbeantwortete Anforderung („Keine Antwort seit …“, zweite Zeile) aus einem früheren Lauf; nach `down && up` grün | Seed-Zustand wiederhergestellt |

e2e-feedruns und e2e-feeds-stable nutzen ausschließlich `page.route`-Mocks (kein Abruf an irgendeine Quelle); geprüft vor dem Lauf.

## B) Abdeckung der Liste

Legende: **S** = Skript, **R** = Rust-Test, **N** = neu in `e2e-functional.mjs` getestet.

| Punkt | Abdeckung | Ergebnis |
| --- | --- | --- |
| Anmeldung, falsches Passwort | N (unbekannter Benutzer und falsches Passwort gleiche Antwort, Cookie HttpOnly/SameSite=Strict, CSRF 403); R `server/tests/api.rs` | bestanden |
| Sperre nach 10 Versuchen | N (429 mit Retry-After beim 11. Versuch seit Serverstart, auch richtiges Passwort gesperrt, danach `restart-server`) | bestanden |
| Passwortwechsel und zurück | N (falsch 403, kurz 400, gleich 400, Wechsel, altes ungültig, Rückgabe auf Dateipasswort, Notausgang im `finally`) | bestanden |
| Host anlegen, Token einmalig | N (Format, nicht in Liste/Detail, kein Hash, Duplikat 409, ungültige Namen 400) | bestanden |
| Report mit Token, ungültiger Token | N (401 ohne/falsch, 400 bei kaputtem JSON, Daten erscheinen) | bestanden |
| Check-in ohne/mit Anfrage, genau ein `true` je Anforderung | N (auch Long-Poll, Cooldown 429 mit Retry-After); S `e2e-checkin.mjs` (echter Agent und UI) | bestanden |
| „Daten jetzt abrufen“ (einzeln, alle) | N, S `e2e-checkin.mjs`, `e2e-agents.mjs` | bestanden |
| Token erneuern (alter Token 401), Host löschen | N (alter Token 401 für Report und Check-in, 404-Fälle, Token des gelöschten Hosts 401) | bestanden |
| Agent-Binary | N: `set-token --stdin` (0600), Lauf, `checkin`, `status`, falscher Token Exit 4, in temporärem Verzeichnis ohne Root, Token nie ausgegeben; R `agent/tests/cli.rs` | bestanden |
| Watchlist: Stern, nur Watchlist, Entfernen mit Rückgängig | N (API); S `e2e-watchlist.mjs` (UI, Rückgängig, Zeitgeber) | bestanden |
| Filter (Betrifft, Debian, Ubuntu) | N (Teilmengen, Kombinationen, Alt-URLs) | bestanden |
| Sortierungen | N (4 Sorten x 2 Richtungen, Monotonie von latest und level, ungültig 400) | bestanden |
| Paginierung „Weitere laden“ | N (limit/offset ohne Doppelte, Grenzwerte). UI-Knopf: Seed hat nur 9 CVEs, Seitengröße 100, daher in N übersprungen (SKIP); S `e2e-cves-toolbar.mjs` mit erzeugten Zeilen | API bestanden, UI-Knopf nur über Mock-Skript |
| Suche mit Sonderzeichen | N (café, 日本語, Emoji, `' " ; -- % _ \`, 300 Zeichen, Nullbyte, HTML, SQL-Einschleusung): nie 5xx, `%` ist kein Platzhalter | bestanden |
| Quelle anlegen, Duplikat, HTML im Namen | N (Typ osv; Name und Konfiguration doppelt 409; Name 41 Zeichen/Zeilenumbruch 400; HTML als Text, kein Skript) | bestanden |
| SSRF bei Quellen | N: Loopback (auch `localhost`, `127.1`, Dezimal-IP, `::1`), private Netze, Metadaten-IP, `file://`, `ftp://`, Zugangsdaten in der URL werden abgelehnt (400), auch beim Ändern. Annahme eines öffentlichen Ziels nicht testbar ohne DNS/Internet; R `server/tests/cve.rs`, `server/src/notify/ssrf.rs` | bestanden / Annahme nicht geprüft |
| Quelle abschalten/einschalten | N (Ubuntu aus: Ubuntu-Hosts `cve_unknown > 0`, keine Ubuntu-CVE als verwundbar, nie `ok`; UI zeigt „CVE-Lage unbekannt“; ein: wieder bewertet; Abruf einer abgeschalteten Quelle 400) | bestanden |
| Quelle löschen, Folgen für Hosts | N (verwaltete Quelle 204/404; Debian-Quelle gelöscht: Debian-Hosts unbekannt, nie grün, Proxmox nie grün) | bestanden |
| Abruf: Erfolg, 304 | N (Mock `fresh` bzw. `ok`) | bestanden |
| Abruf: 503 mit Retry-After | N (Wiederholung nach der genannten Zeit, 1,2 s) | bestanden |
| Abruf: 503 ohne Retry-After | N (Wiederholungen mit Backoff, dann `failed`) | bestanden |
| Abruf: 422 | N (`failed`, keine Wiederholung) | bestanden |
| Abruf: Zeitüberschreitung | N, nur mit `PATCHWATCH_CONFIG` (`request_timeout_secs = 2`, `retries = 2`): `failed` nach 4,3 s, Text „Verbindung zu Debian fehlgeschlagen“. Mit dem Standard (120 s x 3) in einem Lauf nicht praktikabel; das Skript meldet dann FAIL mit Hinweis | bestanden (mit Konfiguration) |
| „Alle abrufen“ | N (202 mit Läufen; direkt danach nichts gestartet, `too_soon` übersprungen) | bestanden |
| 409 bei laufendem Lauf | N (Mock `hang`; 409 mit `run_id`; „Alle abrufen“ nennt den laufenden Lauf) | bestanden |
| 429 `too_soon`, 428 `backoff`, 429 `backoff_limited` | N (Mindestabstand wird per UPDATE auf `feed_runs.created_at` der Wegwerf-Datenbank verkürzt) | bestanden |
| Kanäle: Geheimnis nur schreibend | N (nur mit `PATCHWATCH_SECRET_KEY`): Antwort, Liste, Einstellungen ohne Geheimnis, in der Datenbank kein Klartext; R `server/tests/notify.rs`, `channel_secrets.rs` | bestanden (mit Schlüssel) |
| Kanäle: Ereignisauswahl | N (speichern, lesen, unbekannte Ereignisart 400, unbekannter Kanal 404) | bestanden |
| Kanäle: Testnachricht an Loopback | N (`ok:false`, „nicht erreichbar“, am lokalen Empfänger keine Verbindung; Metadaten-IP ebenso). Zustellung selbst: nicht ohne Abschwächung testbar; R `server/tests/notify.rs` (`notify_job_delivers_and_records_generic_error`, `channel_formats_and_generic_errors`, `loopback_and_metadata_targets_are_blocked_even_when_allowlisted`) | bestanden / Zustellung über Rust-Tests |
| Toasts | S `e2e-toasts.mjs`, `e2e-copy.mjs`, `e2e-feedruns.mjs` | bestanden |
| WebSocket | N (ohne Session 401, falsche Origin 403, mit Session 101 und Ereignis `report_requested` kommt an); R `server/tests/live.rs` | bestanden |
| Profilbild | N (SVG, getarntes SVG, zu groß, kaputt, ohne Anmeldung, Entfernen); S `e2e-avatar.mjs` (gültig, UI); R `server/tests/avatar.rs` | bestanden |

## Fehler

Es wurde kein Produktfehler gefunden; alle Abweichungen waren veraltete Skripte oder Zustände der Umgebung (Tabelle A). Es gibt daher
keine Fix-Commits am Server oder an der Oberfläche. Beobachtungen ohne Handlungsbedarf:

- Ein Zeitlimit beim Abruf erscheint im Lauf als „Netzwerkfehler: error sending request“ (die Ursache wird bewusst ohne URL gekürzt),
  in der Quellenliste als „Verbindung zu Debian fehlgeschlagen“. Verständlich, nennt aber das Zeitlimit nicht.
- Falsches aktuelles Passwort beim Wechsel liefert 403 (nicht 401), damit die Oberfläche nicht abmeldet.
- Ist ein Host wegen dringlicherer Zustände (Sicherheitsupdates, Neustart) im Gesamtstatus nicht „CVE-Lage unbekannt“, steht das
  Unbekannte in `cve_unknown` (Anzahl) und in der CVE-Liste; nie „ok“.

## Nicht geprüft

- Annahme einer öffentlichen Quellen-Adresse und die Zustellung von Benachrichtigungen an ein echtes Ziel (kein Internet/DNS, SSRF-Schutz
  bleibt): nur über Rust-Tests.
- UI-Knopf „Weitere laden“ gegen den Seed (nur 9 CVEs): nur über `e2e-cves-toolbar.mjs` mit erzeugten Zeilen.
- Ubuntu-/Debian-/OSV-/NVD-/KEV-Abrufe gegen echte Quellen (verboten): nur Mock.

## Endlauf (Seed-Zustand, nacheinander)

Reihenfolge: `down && up`, e2e-functional (189 OK, 1 SKIP, Exit 0), `down && up`, die 14 Skripte aus A, e2e-checkin (Exit 0), `down && up`,
layout-check (160 Prüfungen, 0 Verstöße), a11y (keine Verstöße). Alle Skripte aus A grün, außer:

- `e2e-dialogs` scheiterte im Endlauf einmal bei „390/dark: Fokus kehrt zur Schaltfläche zurück“, in drei Wiederholungen einmal (zwei grün),
  im ersten Lauf grün: zeitabhängig (Fokusrückgabe nach dem Schließen des Bottom-Sheets), nicht untersucht, nicht behoben. **Offen: flackernder Test.**
