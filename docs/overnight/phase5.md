# Nachtlauf 2026-11-12: Phase 5, Daten, Zeit, Robustheit (nur Code-Review)

Alles am Code hergeleitet (Opus-Agent), NICHT ausgeführt: keine Migrationsläufe, kein Lasttest, kein
Datenbank-Ausfalltest (Speicherregel). Die Funde sind Hypothesen mit Beleg im Code; jeder nennt den Test, der ihn
bestätigen würde. Nichts geändert.

# Phase 5: Robustheit (nur Code-Review)

**Alle Aussagen sind am Code hergeleitet und nicht ausgeführt.** Es gab keine Builds, keine Tests, keine Datenbank und keinen Browser.
Stand: Worktree `/home/claude/patchwatch-night`, Branch `overnight/2026-11-12`, HEAD `01ca761`. Das Verhalten von sqlx habe ich im
Quelltext der Abhängigkeit nachgelesen (`~/.cargo/registry/src/*/sqlx-core-0.8.6`, `sqlx-postgres-0.8.6`). `server/src/cve/eval.rs` ist
kein Prüfgegenstand.

Funde: **hoch 0 · mittel 4 · niedrig 9**

---

## Funde

### M1 (mittel): Doppelte Paketnamen im Report führen zu 500, der Host meldet nie wieder erfolgreich
- **Ort:** `server/src/routes/report.rs:266-279`, zusammen mit `agent/src/collect/packages.rs:29-36`
- **Beleg:** `INSERT INTO host_packages … SELECT … FROM UNNEST(...) ON CONFLICT (host_id, name) DO UPDATE …`. Der Primärschlüssel ist
  `(host_id, name)` (`0001_init.sql:53`). Der Agent liest `dpkg-query -W -f '${Package}\t…'`. `${Package}` ist der Name ohne
  Architektur, auf Multiarch-Hosts (z. B. `libc6:amd64` und `libc6:i386`) kommt derselbe Name also zweimal vor. PostgreSQL bricht dann
  mit 21000 ab („ON CONFLICT DO UPDATE command cannot affect row a second time“). Das wird zu `ApiError::Internal` und damit zu 500.
  Die ganze Report-Transaktion wird zurückgerollt. Nach 26 h steht der Host auf „meldet sich nicht“, obwohl der Agent läuft. Betroffen
  ist nur, wer `include_packages = true` gesetzt hat (Voreinstellung `false`, `install.sh:268`). Für diese Hosts ist der Fehler aber
  dauerhaft.
- **Fix:** Der Server dedupliziert die Paketliste vor dem UNNEST nach `name` (oder lehnt Duplikate mit 400 ab), und der Agent schickt
  `${binary:Package}` bzw. dedupliziert selbst.
- **Test:** Integrationstest `POST /api/v1/report` mit zwei Paketen `{"name":"libc6","version":"2.36-9"}`. Erwartet wird 204 bzw. 400,
  heute vermutlich 500.

### M2 (mittel): Der Agent wiederholt einen fehlgeschlagenen Tagesreport nicht, eine kurze Störung zur Mittagszeit macht alle Hosts „stale“
- **Ort:** `agent/src/main.rs:121` (ein einziger `send::send`), `install.sh:310-318` (Timer `OnCalendar=12:00`,
  `RandomizedDelaySec=30min`), `server/src/config.rs:232` (`stale_after_hours: 26`)
- **Beleg:** Bei 5xx oder Netzfehler endet der Agent mit Exit-Code 4. Einen Retry oder `Restart=` gibt es nicht, der nächste Lauf kommt
  erst am Folgetag um 12:00. Sind Server oder DB zwischen 12:00 und 12:30 nicht erreichbar (z. B. bei einem Update), entsteht eine
  Lücke von etwa 48 h. Ab etwa 26 h nach dem letzten Report werden alle Hosts „stale“, und es gibt einen Sammel-Alarm `agent_silent`.
  Den Check-in-Timer gibt es zwar, er sendet aber nur auf Anforderung des Servers.
- **Fix:** Bei 5xx oder Netzfehler wiederholt der Agent mit Backoff (z. B. 3 Versuche in 10 min innerhalb von `TimeoutStartSec`).
  Alternativ fordert der Server über den vorhandenen Check-in einen Report an, sobald `last_report_at` älter als etwa 24 h ist.
- **Test:** Agent-Test mit einem Mock-Server, der zuerst 503 und dann 204 liefert: Es wird erwartet, dass der Report ankommt.

### M3 (mittel): Der Report speichert unbekannte Felder ungeprüft in `reports.raw` (NUL führt zu 500, bis 4 MiB pro Report)
- **Ort:** `server/src/routes/report.rs:200-211`, `:289-301` (bind `&raw`), `:11` (`MAX_BODY = 4 MiB`), `:198` (300 Reports/min/IP)
- **Beleg:** `ReportIn` hat kein `deny_unknown_fields`, und `raw` ist das komplette JSON ohne `packages` und `updates.items`.
  1. Ein unbekanntes Feld wie `"x":"a\u0000"` wird beim jsonb-Eingang abgelehnt (22P05) und endet als 500 statt 400.
  2. Ein Host-Token kann pro Report bis zu etwa 4 MiB Ballast in die Historie schreiben. Bei 300/min sind das grob 1,2 GB/min
     DB-Wachstum, bis das Cleanup greift.
- **Fix:** `raw` aus dem geprüften `ReportIn` neu serialisieren (nur bekannte Felder), oder zumindest Größe (z. B. 64 KB) und NUL prüfen.
  Zusätzlich ein Rate-Limit je `host_id` einführen (z. B. 1 Report pro Minute).
- **Test:** Report mit einem Zusatzfeld `"x":"\u0000"` soll 400 liefern. Ein Report mit einem 3 MB großen Zusatzfeld soll 400 liefern
  oder ein `raw` ohne das Feld ergeben.

### M4 (mittel): Hintergrund-Tasks werden nach Fehlstart oder Panic nie neu gestartet, und `/readyz` bleibt grün
- **Ort:** `server/src/worker.rs:13-14` (`PgListener::connect_with(...).await?` und `listen_all(...).await?`), `server/src/main.rs:156-161`
  (loggt nur „Worker beendet“), `server/src/main.rs:153-155` (Live-, Minuten- und Feed-Scheduler als nackte `tokio::spawn`),
  `server/src/cve/refresh.rs:674` (geplante Läufe direkt mit `await` im Scheduler-Task)
- **Beleg:**
  - Scheitert der Listener-Aufbau beim Start (DB-Neustart direkt nach den Migrationen, Pool kurz erschöpft), endet `worker::run`
    endgültig. Dann gibt es keine Benachrichtigungen, keine Tageszusammenfassung, kein Cleanup und keine Events mehr, während die API
    normal weiterläuft.
  - Ein Panic im geplanten Feed-Pfad beendet den ganzen Feed-Scheduler. Nur `execute_all` (manuelle Läufe, `runs.rs:551-565`) fängt
    Panics über `JoinSet` ab.
  - Ein Panic in `schedule_once` beendet die Stale-Erkennung (siehe N9).
  - `panic = "unwind"` schützt nur Handler, die hinter `CatchPanicLayer` laufen.
  - Einen konkreten Panic-Ort in diesen Pfaden habe ich nicht gefunden, abgesehen von N9.
- **Fix:** Jeden Hintergrund-Task in einer Supervisor-Schleife starten (`loop { spawn(..).await; warn; sleep(5s) }`), wobei
  `JoinError::is_panic` wie ein Fehler behandelt wird. Den Listener-Aufbau in `worker::run` innerhalb der Schleife mit Retry machen.
- **Test:** Unit-Test mit einem Supervisor, dessen Task beim ersten Mal paniken soll und beim zweiten Mal läuft. Für den Worker ein
  Integrationstest: DB-Verbindungen kurz nach dem Start per `pg_terminate_backend` trennen, dann muss ein Job weiterhin verarbeitet werden.

### N1 (niedrig): NUL in JSON-Bodys führt zu 500 statt 400 (die URI-Prüfung deckt Bodys nicht ab)
- **Ort:**
  - `server/src/routes/auth.rs:41-46`: Login-`username`, auch **ohne Anmeldung** erreichbar
  - `server/src/routes/cves.rs:580-595`: Watchlist-`note`, ohne Steuerzeichenprüfung
  - `server/src/routes/settings.rs:108`: Schlüssel von `feed_intervals`
  - `server/src/routes/oidc.rs:205-262`: `issuer`, `client_id`, `scopes` und die Listen landen in jsonb, ohne Längenlimit
  - `server/src/routes/mod.rs:139-152` prüft nur `%00` in der URI
- **Beleg:** `"username":"a\u0000"` gelangt als Text-Parameter an PostgreSQL. Dort folgt 22021 („invalid byte sequence … 0x00“), dann
  `?` und `ApiError::Internal`, also 500 mit einem Error-Log je Anfrage.
- **Fix:** Einen gemeinsamen `Json`-Extractor bauen, der nach dem Parsen rekursiv jeden String mit `'\0'` mit 400 ablehnt. Dazu
  Längenlimits für die OIDC-Felder.
- **Test:** `POST /auth/login` mit `{"username":"a\u0000","password":"x"}` soll 400 liefern, ebenso `PUT /watchlist/CVE-2024-1086`
  mit `note` = `"\u0000"`.

### N2 (niedrig): Bei einem DB-Ausfall antwortet die API nach bis zu 5 s mit 500 „interner Fehler“, nicht mit 503
- **Ort:** `server/src/error.rs:23-27` (jeder `sqlx::Error` wird zu `Internal`), `:45-51`, `server/src/main.rs:31`
  (`acquire_timeout(5s)`), `server/src/extract.rs` (`load_admin`: auch die Anmeldeprüfung liefert 500)
- **Beleg:** Nur `/readyz` antwortet mit 503 (`routes/health.rs`). Alle anderen Routen hängen bis zu 5 s und liefern dann 500. Das Web
  zeigt „Serverfehler (HTTP 500)“ (`web/src/lib/apiErrors.ts:23`), der Agent bekommt 500.
- **Fix:** `sqlx::Error::PoolTimedOut`, `Io` und `PoolClosed` auf 503 mit `Retry-After` und einem eigenen Code
  (`"code":"db_unavailable"`) abbilden.
- **Test:** Einen Pool gegen einen geschlossenen Port mit `acquire_timeout` 1 s aufbauen, dann `GET /api/v1/hosts` aufrufen: erwartet
  wird 503.

### N3 (niedrig): Im Web führt jeder Fehler von `/auth/me` zur Login-Seite, und bei 500 heißt es „Server nicht erreichbar“
- **Ort:** `web/src/components/AuthProvider.tsx:40-42` (`.catch(() => router.replace("/login"))`), `web/src/app/login/page.tsx:41`
- **Beleg:** 500, 502, 503 und Netzfehler sehen wie eine Abmeldung aus. Nach der Erholung muss man manuell zurücknavigieren, obwohl
  die Sitzung noch gültig ist.
- **Fix:** Nur bei 401 umleiten. Sonst ein Banner „Server/Datenbank nicht erreichbar“ mit „Erneut versuchen“ zeigen.
- **Test:** Komponenten- oder E2E-Test mit `/auth/me` auf 503: erwartet werden ein Banner und keine URL-Änderung.

### N4 (niedrig): Es gibt keine `error.tsx` und keine `global-error.tsx`
- **Ort:** `web/src/app/**` (gesucht wurde nach `error.tsx`, `global-error.tsx`, `ErrorBoundary`, `componentDidCatch`, ohne Treffer)
- **Beleg:** Eine Exception beim Rendern ergibt die Next-Standardseite „Application error“, also praktisch eine weiße Seite.
  API-Fehler selbst laufen über `useApi` als Zustand, nicht als Exception. Einen konkreten Auslöser habe ich nicht gefunden.
- **Fix:** `app/(app)/error.tsx` (mit `reset`) und `app/global-error.tsx` mit einer schlichten deutschen Fehlerseite ergänzen.
- **Test:** E2E-Test mit einer Testseite, die beim Rendern wirft: erwartet wird die Fehlerseite mit Knopf statt einer leeren Seite.

### N5 (niedrig): Startet die Datenbank verzögert, bricht der Server nach etwa 5 s ab
- **Ort:** `server/src/main.rs:28-35`, `:88-89`
- **Beleg:** sqlx wiederholt nur `ConnectionRefused` und transiente Fehler (z. B. 57P03 „starting up“), und das nur bis zum
  `acquire_timeout` von 5 s (`sqlx-core-0.8.6/src/pool/inner.rs:330-391`). Ein DNS-Fehler (Hostname `postgres` noch unbekannt) führt
  sofort zum Abbruch. Danach endet `main` mit einem Fehler. In Compose fangen das `depends_on: service_healthy` und
  `restart: unless-stopped` ab, bei Betrieb ohne Compose oder ohne Restart-Policy nicht.
- **Fix:** In `connect()` eine eigene Retry-Schleife mit Backoff bis z. B. 60 s einbauen und jeden Versuch loggen.
- **Test:** Den Server mit einer DB-URL auf einen noch geschlossenen Port starten und den Port nach 10 s öffnen: erwartet wird, dass
  der Server danach läuft.

### N6 (niedrig): Zwei Server an einer DB stören sich gegenseitig (das Design setzt genau einen Prozess voraus)
- **Ort:** `server/src/cve/runs.rs:297-311` (`recover_on_start`, Kommentar „genau einen Server-Prozess je Datenbank“),
  `server/src/cve/refresh.rs:637`, `server/src/state.rs:14-16` (`run_gate` und `kind_locks` nur im Prozessspeicher),
  `server/src/admin.rs:88-104` mit `:46` (`ON CONFLICT (username) DO UPDATE`)
- **Beleg:**
  - Server B markiert beim Start die laufenden Feed-Läufe von A als `interrupted`. Danach erlaubt der Unique-Index einen neuen Lauf,
    sodass dieselbe Quelle doppelt abgerufen und geschrieben wird.
  - Beim allerersten Start legen beide den Admin an und geben je ein Zufallspasswort aus. Gültig ist nur das des zuletzt Schreibenden.
  - Migrationen (Advisory Lock), die Job-Queue (SKIP LOCKED), `claim_report_run` und der Dedupe der Tageszusammenfassung sind dagegen
    mehrprozessfest.
- **Fix:** Feed-Ausführung und Bootstrap unter `pg_advisory_lock` bzw. `pg_try_advisory_lock` legen, z. B. eine Sperre je Quelle und
  eine für den Bootstrap.
- **Test:** Zwei `AppState` auf dieselbe Test-DB, dann `recover_on_start` im zweiten aufrufen, während im ersten ein Lauf läuft:
  erwartet wird, dass der Lauf nicht unterbrochen wird.

### N7 (niedrig): Die tägliche Report-Anforderung entfällt am Tag der Sommerzeitumstellung ganz, die Tageszusammenfassung kommt dagegen um 03:00
- **Ort:** `server/src/schedule.rs:104-110` (`LocalResult::None => return None`, „der Tag entfällt“), dagegen `server/src/worker.rs:283-285`
  (`local.time() >= summary_time` führt in der Lücke zum Versand um 03:00)
- **Beleg:** Der Test `daily_skips_nonexistent_dst_time` (`schedule.rs:437-448`) schreibt das Auslassen bewusst fest. Die beiden
  Zeitpläne verhalten sich also unterschiedlich. Folgen hat das kaum, weil der Agent-Timer ohnehin täglich meldet.
- **Fix:** Bei `LocalResult::None` den ersten gültigen Zeitpunkt danach nehmen (`d.and_time(t) + 1h`), so wie bei der Zusammenfassung.
- **Test:** Den bestehenden Test auf `last_due(None, 2026-03-29T12:00Z) == Some(2026-03-29T01:00Z)` umstellen.

### N8 (niedrig): Die Bootzeit verschiebt sich bei jedem Report um einige Sekunden
- **Ort:** `agent/src/report.rs:65-82` (`uptime_seconds` wird nach `updates::collect` und vor `proxmox::collect`/`packages::collect`
  gelesen), `server/src/routes/report.rs:218/235` (`last_report_at` = Empfangszeit beim Server), `web/src/lib/format.ts:45-49`
  (Boot = Reportzeit minus Uptime)
- **Beleg:** Die Bootzeit liegt um die Dauer von Paketsammlung, Serialisierung und Netzweg zu spät. Die Anzeige hat Minutenauflösung
  (`shortDateTime`), deshalb springt „gestartet HH:MM“ gelegentlich um eine Minute. Eine negative Uptime ist ausgeschlossen
  (`report.rs:171`, `format.ts:46`, `Math.max(0, …)`).
- **Fix:** Der Agent liest die Uptime als letzten Schritt vor dem Senden, oder der Server speichert `boot_at` und übernimmt neue Werte
  nur bei einer Abweichung über 120 s.
- **Test:** Agent-Unit-Test, dass `/proc/uptime` nach `packages::collect` gelesen wird (Reihenfolge im Fake-Runner protokollieren).

### N9 (niedrig): Konfigurationswerte haben keine Obergrenze, ein riesiger `STALE_AFTER_HOURS` löst einen Panic im Minuten-Scheduler aus
- **Ort:** `server/src/config.rs:436-441` (nur `>= 1` geprüft), `server/src/schedule.rs:221-222` (`Duration::hours(fallback)`),
  `server/src/hostops.rs:233` (`Utc::now() - stale_after`)
- **Beleg:** In der UI gilt 1–720 h, für den Fallback aus der Umgebung gilt keine Grenze. Etwa ab 2,3·10⁹ h kommt es in chrono zu
  „`DateTime - TimeDelta` overflowed“ bzw. „TimeDelta::hours out of bounds“. Das ist ein Panic in `schedule_once`, und nach M4 ist dann
  die Stale-Erkennung dauerhaft aus. Dasselbe gilt sinngemäß für `REPORT_RETENTION_DAYS`: Dort sättigt `as i32` in `worker.rs:194`,
  daraus wird „interval out of range“ und der Cleanup-Job scheitert.
- **Fix:** In `Config::validate` dieselben Bereiche wie in der UI prüfen (`STALE_HOURS_RANGE`, `RETENTION_RANGE`).
- **Test:** `Config::parse` mit `STALE_AFTER_HOURS=100000000000` soll einen Fehler liefern.

---

## Geprüft und in Ordnung (am Code hergeleitet)

**Migrationen**
- Die Dateien `0001`–`0020` sind lückenlos und eindeutig nummeriert. Laut `git log` hat **jede Datei genau einen Commit**, ist seit dem
  Anlegen also unverändert. Die sqlx-Prüfsummen bleiben stabil, ein zweiter Start ist ein No-op.
- Der sqlx-0.8.6-Migrator läuft mit `locking: true`. Das bedeutet `pg_advisory_lock` (`sqlx-postgres-0.8.6/src/migrate.rs:170-182`),
  gleichzeitige Starts werden also serialisiert. Jede Migration läuft in einer eigenen Transaktion (keine nutzt `-- no-transaction`),
  ein Absturz mitten in einer Migration führt zum Rollback. Die Sperre gilt für die Sitzung und fällt beim Absturz weg.
- Weitgehend additiv. Ausnahmen:
  - `0004` erweitert ein CHECK-Constraint.
  - `0005` benennt `name` in `id` um, ohne Datenverlust; ein Rückschritt auf ältere Binaries ist danach ausgeschlossen.
  - `0011`, `0015` und `0016` ändern nur harmlose Daten (`usable_until`, Validatoren, `last_synced_at`).
  - Ein älteres Binary auf einer neueren DB bricht absichtlich ab (`VersionMissing`).
- Das CHECK-Constraint für `notification_channels.kind` (`0004`) stimmt mit `KINDS` (`notify/channels.rs:16-18`) überein.

**Absturz und hängende Läufe**
- Job-Queue (`jobs.rs:35-52`):
  - Jobs „in Arbeit“ werden über die Lease `locked_at < now() - 5 min` wieder frei.
  - `attempts` wird beim Claim gezählt, wiederholte Abstürze zählen also mit.
  - Backoff höchstens 1 h, höchstens 8 Versuche.
  - Zustellung „at least once“: Ein Absturz nach dem Senden und vor `complete` führt zu einer doppelten Meldung. Das ist akzeptabel.
- Events (`worker.rs:40-107`): Verarbeitung in einer Transaktion mit `FOR UPDATE SKIP LOCKED`. Jobs und `pg_notify` sind
  transaktional.
- `feed_runs`:
  - `recover_on_start` und `sweep_stale` (alle 30 s) erkennen fehlende Lebenszeichen nach 120 s.
  - Der Heartbeat kommt alle ≤ 10 s, auch während auf die Sperre gewartet wird (`runs.rs:464-489`, `:568-575`).
  - Die harte Obergrenze beträgt `stall_timeout × 4`.
  - Das abschließende UPDATE überschreibt auch Läufe, die versehentlich als unterbrochen markiert wurden.
- Report-Anforderung: Geht eine Anforderung verloren, wird sie nach 10 min erneut ausgeliefert (`routes/agent.rs:17`, `:78-86`).

**Zeit**
- Tageszusammenfassung (`worker.rs:273-295`): An beiden Umstellungstagen wird sie **genau einmal** gesendet. Der Schlüssel ist
  `daily:<kanal>:<lokales Datum>` mit `ON CONFLICT (dedupe_key) DO NOTHING` (`0001_init.sql:132`) und der Bedingung
  `local.time() >= summary_time`.
  - März, Lücke 02:00–03:00: Der Versand erfolgt um 03:00.
  - Oktober, 02:xx doppelt: Das zweite Vorkommen wird dedupliziert.
- Feed-Zeitpläne (`refresh.rs:622-631`) und der Report-Zeitplan „Intervall“ rechnen mit reinen Zeitspannen in UTC und hängen nicht
  von der Zeitzone ab. Beim Zeitplan „Täglich“ wird bei der doppelten Stunde das erste Vorkommen genommen, er läuft also einmal.
- Relative Zeit im Web (`web/src/lib/format.ts:6-23`): Unter 24 h wird in Stunden gerechnet, sonst in Berliner Kalendertagen über
  `Intl.DateTimeFormat("en-CA", {timeZone:"Europe/Berlin"})`. Am 25-h-Tag zeigt ein Report von vor 24–25 h „heute“; das ist für den
  Kalender korrekt.
- „Zuletzt gemeldet“ ist die **Serverzeit** (`report.rs:218`, `:227`). Das `collected_at_unix` des Agents fehlt in `ReportIn` und
  steht nur in `raw`. Eine um 1 h falsche Agent-Uhr wirkt sich daher nicht aus. `checkin::due` behandelt Zeitstempel in der Zukunft
  (`agent/src/checkin.rs:31-36`).
- Uptime: `/proc/uptime` ist monoton und hängt nicht von der Wanduhr des Agents ab. Negative Werte werden abgelehnt. Nach einem
  Neustart stimmt der Wert mit dem nächsten Report wieder.
- Stale-Logik 26 h:
  - SQL `last_report_at < now-26h` (`hostops.rs:235`) und Rust `now - t > stale_after` (`status.rs:61`) sind beide strikt, und beide
    nehmen die Zeit aus Rust.
  - Durchgehend `timestamptz`.
  - Agent-Timer 12:00 plus ≤ 30 min Zufall ergibt höchstens 24,5 h Abstand bzw. 25,5 h über die Oktoberumstellung, also weniger als
    26 h.
  - Hosts, die schon „stale“ sind, berechnet erst der nächste Report neu (Debian/Ubuntu zusätzlich alle 30 s über `gate_hosts`).

**Eingaben**
- `limit` wird überall geklemmt (`hosts.rs:140`, `:273`; `cves.rs:387`; `feeds.rs:864-867`), `offset` ist ein `i64` mit `max(0)`
  (direkt im SQL steht nur eine geklemmte Zahl).
- `Path<i64>` und Query-Typen lehnt axum mit 4xx ab.
- `%00` in der URI wird global abgewiesen.
- `cves q` lehnt Steuerzeichen ab, und das UTF-8-Slicing ist korrigiert (`cves.rs:253-259`, `:280`).
- Die Report-Felder werden nach Zeichensatz, Länge, Anzahl und Bereich geprüft (`report.rs:89-189`). Die Kanal-Konfiguration
  (`notifications.rs:120-130`) und Feed-Namen (`feeds.rs:466-479`) dürfen keine Steuerzeichen enthalten.
- Die PNG/WebP-Parser prüfen ihre Grenzen (`avatar.rs:58-150`).
- In den Routen gibt es außerhalb von Tests kein `unwrap`/`expect` auf Eingaben.
- `CatchPanicLayer` mit `panic = "unwind"` macht aus einem Panic im Handler eine 500, statt den Prozess zu beenden.

**DB-Ausfall und Listener**
- Der Live-Listener baut die Verbindung nach 3 s neu auf und sendet danach `resync` (`live.rs:287-308`). Hängt ein WS-Client hinterher,
  bekommt er ebenfalls `resync` (`routes/live.rs:95-97`). Der WS im Web verbindet sich mit exponentiellem Backoff bis 30 s neu und
  sendet `resync` (`web/src/lib/live.tsx:76-85`).
- Der Worker-Listener verbindet sich nach einem Verbindungsverlust über den Auto-Reconnect von sqlx neu
  (`sqlx-postgres-0.8.6/src/listener.rs:280-303`) und fragt außerdem alle 15 s nach. Funktional erholt er sich also, Probleme macht
  nur der Fehlstart (siehe M4).
- Compose: Healthcheck für Postgres, `depends_on: service_healthy`, `restart: unless-stopped`. Der Server-Healthcheck nutzt `/readyz`.

---

## Nur durch Ausführung klärbar
- **Worker-Listener bei ECONNRESET:** sqlx reicht `ConnectionReset` als `Err` weiter, nicht als Reconnect-Fall
  (`listener.rs:283-290`), und der Worker ignoriert den Fehler (`worker.rs:19`). Heilt der nächste `recv` (EOF führt zum Reconnect),
  oder läuft die Schleife ohne Pause? Prüfen mit `pg_terminate_backend` bzw. einem Postgres-Neustart und einem Blick auf CPU und Log.
- **Abbruch von `recv()` durch `tokio::time::timeout`, während neu verbunden wird** (`connect_if_needed` nimmt `buffer_tx`): Geht
  dabei der Benachrichtigungskanal dauerhaft verloren, sodass nur noch alle 15 s nachgefragt wird? Prüfen durch Messen der
  Job-Latenz nach dem Reconnect.
- Wie lange dauert `0015` (Tabellen-Rewrite durch `GENERATED … STORED`) bei großen `cve_source_status` beim Upgrade?
- Die genauen SQLSTATEs für NUL (22021 Text, 22P05 jsonb) und Duplikate (21000) samt 500-Antwort per Test bestätigen (N1, M1, M3).
- Rendern die Web-Seiten bei 5xx überall einen Fehlerzustand (`useApi`), und erscheint bei einer Render-Exception eine weiße Seite (N4)?
- Lastverhalten während eines DB-Ausfalls: Check-ins im Minutentakt, `acquire_timeout` 5 s, Pool 10, davon 2 dauerhaft für Listener
  belegt. Gibt es eine Log-Flut oder blockierte Worker?
- Nebenbefund zur Datenqualität, keine Robustheitsfrage: `dpkg-query -W` listet auch Pakete im Zustand „config-files“ (rc). Diese
  würden als installiert gemeldet. Auf einem Host prüfen und gegebenenfalls `${db:Status-Abbrev}` mitschicken und filtern.
