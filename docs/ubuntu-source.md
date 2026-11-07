# Ubuntu-Quelle: Messungen, Entscheidung, Regeln

Stand der Messungen: 2026-11-06 (Entwicklungs-VM, nur lesend, 5 Anfragen an die API, nie tiefer als `offset=20`, je
mindestens 6 s Pause; sonst nur HEAD-Anfragen und **ein** einmaliger Download einer OVAL-Datei).

## Problem

Der bisherige Erstabruf blätterte `https://ubuntu.com/security/cves.json?package=linux&limit=20&offset=N&order=descending&sort_by=updated`
bis zum Horizont (rund 1.100 Seiten). Das scheitert an der API, nicht am Netz.

## Was der Server bisher sendet

| | |
|---|---|
| URL | `{ubuntu_url}/security/cves.json?package=linux&limit=20&offset=N&order=descending&sort_by=updated` |
| Header | `accept: application/json`, `accept-encoding: gzip` (reqwest), kein Cookie |
| User-Agent | `patchwatch-server/<Version> (+https://github.com/EinNiki/patchwatch)` |
| Timeout / Versuche | 120 s je Anfrage, 3 Versuche je Seite (Backoff mit Jitter, `Retry-After` bis 15 Min.) |
| Limit je Antwort | 32 MiB (`ubuntu_max_page_bytes`) |

## API-Messungen (diese URL und Varianten)

| Anfrage | Status | Bytes | Zeit | Cache |
|---|---|---|---|---|
| exakt die Server-Parameter, `offset=0` (ohne gzip) | 200 | 29.823.337 | 27,0 s | MISS |
| dieselbe Anfrage 8 s später | 503 (nginx) | 190 | 20,6 s | – |
| ohne `sort_by`/`order`, `offset=0`, `limit=20` | 504 | 93 | 50,1 s | – |
| Server-Parameter mit `limit=5`, `offset=0` (gzip) | 504 | 93 | 50,1 s | – |
| Server-Parameter, `limit=20`, `offset=20` (gzip) | 504 | 93 | 50,1 s | – |

Befunde:

* Die Sortierung ist **nicht** die Ursache: auch ohne `sort_by` und mit nur 5 Einträgen kommt 504.
* Mit `package=linux` ist jede Antwort riesig: 20 Kernel-CVEs sind **29,8 MB** (ein Eintrag 1 bis 2 MB: 171 Paketzeilen
  samt Patches, Hinweisen und Verweisen). Das Erzeugen dauert 20 bis 50 s und läuft in das Zeitlimit von nginx (504/503).
  Ohne Paketfilter sind die Seiten klein (62 KB, 0,3 s aus dem Cache), enthalten dann aber nicht die Kernel-CVEs.
* Die Seitengröße lässt sich nicht beliebig senken: schon 5 Einträge laufen in den Timeout, solange das Backend ausgelastet
  ist. Tiefes Blättern ist damit nicht zuverlässig machbar (offset=1000: 504 nach 50 s, Messung des Betreibers).

## Alternativen für Massendaten (nur HEAD, Statuscodes geprüft)

| Quelle | Status | Content-Length | Last-Modified | ETag | 304 |
|---|---|---|---|---|---|
| `oval/com.ubuntu.jammy.cve.oval.xml.bz2` | 200 | 13.052.297 | 2026-11-05 23:26 | ja | – |
| `oval/com.ubuntu.noble.cve.oval.xml.bz2` | 200 | 11.172.446 | 2026-11-05 22:48 | ja | – |
| `oval/com.ubuntu.resolute.cve.oval.xml.bz2` | 200 | 4.923.985 | 2026-11-05 22:32 | ja | **ja** (If-None-Match und If-Modified-Since) |
| `oval/com.ubuntu.focal.cve.oval.xml.bz2` | 200 | 8.374.009 | 2026-11-05 23:39 | ja | – |
| `oval/com.ubuntu.noble.usn.oval.xml.bz2` | 200 | 1.298.551 | 2026-11-05 22:29 | ja | – |
| `osv/osv-all.tar.xz` (alle Ubuntu-Daten, OSV) | 200 | 60.225.512 | 2026-11-06 06:31 | ja | – |
| `https://security-metadata.canonical.com/` | 301 nach ubuntu.com/security | – | – | – | – |
| `osv/all.zip`, `notices.json.bz2`, `cve/`, `usn/` | 404 | – | – | – | – |

* Die Indexseite `/oval/` listet 132 Dateien: je Release `cve`, `pkg`, `usn` (bionic, focal, jammy, noble, oracular, plucky,
  questing, resolute, stonking, trusty, xenial) sowie Varianten (`fips`, `fips-updates`, `realtime`, `bluefield`).
* OSV: ein einziges Archiv von 60 MB für alles; unterstützt ETag, ist aber für unseren Zweck zu groß (alle Pakete, alle
  Releases) und enthält pro Release ebenfalls nur Fix-Informationen.
* `git ls-remote https://git.launchpad.net/ubuntu-cve-tracker` funktioniert (HEAD `e80c9b3…`, viele Branches). Ein flacher oder
  partieller Klon wäre möglich, aber die Daten liegen dort als Zehntausende Textdateien; ein inkrementelles Fetch bräuchte
  das `git`-Programm und ein Arbeitsverzeichnis auf dem Server. Für einen Dienst, der nur HTTP spricht, unverhältnismäßig.
* Download der **noble**-Datei (einmalig): 11.172.446 Bytes in 0,5 s (CDN), entpackt 240 MB XML, 36.619 Definitionen,
  `bzcat` 4,2 s. Gestreamt zu verarbeiten ist das unkritisch; die ganze Datei darf nie im Speicher liegen.

## Weitere Optionen für offene Fälle (nicht umgesetzt, nur zur Entscheidung)

* **Abfrage je einzelner CVE statt Seiten:** `GET /security/cves/<CVE-ID>.json` liefert eine CVE (kleine Antwort, kein
  Seitenlimit). Sinnvoll als gezielter Abruf für CVEs, die auf Hosts relevant sind (Watchlist, Offen-Liste), nicht für alle
  Zehntausend. Bei der Stichprobenprüfung antwortete der Endpunkt in 3 von 5 Fällen, 2 liefen in Timeout/504: er teilt die
  Überlastung der Listen-API.
* **OSV für Ubuntu:** Massenarchiv `osv/osv-all.tar.xz` (60 MB, siehe oben) oder die OSV-API (`api.osv.dev`, Abfrage je
  Paket/CVE, Ubuntu-Einträge `UBUNTU-CVE-…` mit `affected`-Bereichen). Eigene Infrastruktur, unabhängig von der
  überlasteten Canonical-API; Aussage zu „offen“ (kein Fix) ist dort aber nicht vollständig, noch nicht gemessen.

## Was die OVAL-Dateien über Status sagen (Vergleich mit `cves.json`, noble)

Verglichen wurden die 20 zuletzt geänderten Kernel-CVEs (1.200 Paket-Release-Einträge ohne DNE):

| Status in `cves.json` | OVAL: „behoben“ (mit Version) | OVAL: nur „Kernel läuft“ (offen) | OVAL: nichts |
|---|---|---|---|
| released | **417** | 38 (Realtime-Varianten) | 97 (FIPS, `linux-realtime-6.14`) |
| needed | – | 18 | 4 |
| pending | – | 26 | – |
| ignored | – | 187 | – |
| not-affected | – | – | 413 |

Schlüsse:

1. **Behobene Fälle** bilden die Dateien genau ab, mit Fixversion (Kommentar „kernel 'linux' in noble was vulnerable but has
   been fixed (note: '6.8.0-100.100')“). Für alle in der Datei geführten Varianten stimmen sie mit `cves.json` überein
   (417 von 417). FIPS und Realtime stehen in eigenen Dateien (`fips_*`, `realtime_*`).
2. **Offene Fälle** stehen nur als „Kernel X läuft“ ohne Fixkriterium. Die Datei unterscheidet **nicht** zwischen
   needed, pending und ignored (ignored: 187 von 187 erscheinen als „offen“). Für Realtime-Varianten, die in `cves.json`
   „released“ sind, steht fälschlich „offen“. Aus dem Fehlen eines Eintrags lässt sich nichts ableiten.
3. **Fehlende Einträge sind mehrdeutig.** CVE-2024-1086: In `cves.json` ist noble `not-affected` (vor dem Release
   behoben); in der noble-OVAL-Datei kommt die CVE gar nicht vor. CVE-2026-98432 und CVE-2026-99999 stehen in der noble-Datei
   mit „Kernel `linux` läuft“ (52 Varianten, offen), in `cves.json` ist CVE-2026-99999 für noble 19-mal `pending`, 39-mal
   `needed`, einmal `not-affected`. Die Datei kennt „pending“ nicht.

## Entscheidung: hybrid

* **Massendaten (täglich):** je relevantem Release eine bedingte Anfrage (`If-None-Match`/`If-Modified-Since`, bei 304 geschieht
  nichts), bz2 gestreamt entpackt und gestreamt geparst. Übernommen werden **nur behobene Kernel-Einträge** (`linux` und
  Varianten, Status `fixed` mit Fixversion). Offene Einträge der Datei werden **nicht** gespeichert: daraus würde ein falsches
  „verwundbar“ (Realtime) oder ein verlorenes „Fix angekündigt“; fehlende Information bleibt „unbekannt“.
* **Offene Fälle (stündlich):** die ersten Seiten von `cves.json` bis zum gespeicherten Stand, Seitengröße höchstens 20,
  bei Fehlern 20 → 10 → 5 (nie darunter), bei 422 wird das Maximum gelernt, `Retry-After` gilt (höchstens 15 Minuten),
  eine Anfrage gleichzeitig, 2 s Pause zwischen Seiten, Timeout mindestens 60 s. Scheitert dieser Abruf, ist das kein
  Totalausfall: die Massendaten gelten weiter, aber nur innerhalb ihrer Frische.
* **Rückfallweg:** der bisherige Rückstandsabbau (`ubuntu_mode = "api"`) bleibt erhalten, ist aber nicht mehr der Standard.
  Ein vorhandener Fortschritt wird nie gelöscht, sondern bei Abschluss des Hybridimports in `feed_state.backfill_parked`
  aufbewahrt.

### Regeln für „vollständig“

Ubuntu gilt als **vollständig und nutzbar**, wenn für **jedes relevante Release** (Releases der Ubuntu-Hosts plus
`ubuntu_bulk_releases`) der Import erfolgreich war und `verified_at` (letzter 200 oder 304) nicht älter ist als
`max(3 × täglichem Intervall, 36 Stunden)`. Ist ein Import fehlgeschlagen, ein Release ohne Daten oder die Frische
überschritten, bleibt die Quelle **unvollständig/veraltet**; Hosts dieses Releases zeigen „CVE-Lage unbekannt“, nie grün.
Bestehende Hostbewertungen bleiben erhalten (Rot bleibt rot).

### Statuszuordnung (im Adapter, nicht in `eval.rs`)

| Quelle | Information | normalisiert |
|---|---|---|
| OVAL | Kernel-Variante „war verwundbar, behoben (note: V)“ | `fixed`, Fixversion V |
| OVAL | Kernel-Variante läuft, kein Fixkriterium | **nicht gespeichert** (unbekannt) |
| OVAL | Eintrag fehlt | **nicht gespeichert** (unbekannt) |
| `cves.json` | released + Version | `fixed` |
| `cves.json` | pending + Version | `fix_pending` |
| `cves.json` | needed / deferred / ignored | `vulnerable` |
| `cves.json` | needs-triage, Unbekanntes | `unknown` |
| `cves.json` | not-affected | `not_affected` |
| `cves.json` | DNE | nicht gespeichert |

Gleichstand bei einem Schlüssel `(CVE, Release, Paket)` löst die vorhandene Regel der Ablage auf (der ungünstigere Status
gewinnt innerhalb eines Imports; über Läufe gewinnt der zuletzt geschriebene, beide Quellen stammen von Canonical).

## Erwartete Dauer des ersten vollständigen Imports

Je Release eine Datei von 5 bis 13 MB (CDN, Sekunden) plus lokale Verarbeitung (entpacken und parsen ca. 5 bis 20 s,
Speichern einiger Zehntausend Zeilen): für drei Releases **unter zwei Minuten**, sofern `security-metadata.canonical.com`
erreichbar ist. Das stündliche Blättern der ersten Seiten läuft unabhängig davon.

## Umsetzung (Stand dieser Version)

* **Zustand:** `feed_state.bulk` (JSONB: je Release `etag`, `last_modified`, `verified_at`, `imported_at`, Größe, Ergebnis,
  letzter Fehler mit Statuscode, `Retry-After`, nächster Versuch; dazu `ok` = Ende der Frische je Release, `complete`,
  `relevant` und der Stand des stündlichen Abrufs: Seitengröße, gelerntes Maximum, Fehler, Fortschritt). Der bestätigte
  Cursor bleibt `feed_state.cursor`. Migration 0013 ist rein additiv (`bulk`, `backfill_parked`), nichts wird gelöscht.
* **Nutzbarkeit je Release:** ein Host gilt nur als bewertbar, wenn `bulk.ok.<Release des Hosts>` in der Zukunft liegt
  (`hostops::source_usable_sql`). Fehlt das, zeigt der Host „CVE-Lage unbekannt“ mit Begründung („für jammy fehlen aktuelle
  Massendaten“); andere Releases bleiben bewertbar. `eval.rs` ist unverändert.
* **Fehler im Massenimport** (404/5xx, abgeschnitten, zu groß, kein bz2, XML ohne Ende) verändern gespeicherte Daten nie;
  der Fehler steht in der Anzeige, die Quelle ist dann „unvollständig“ (nie grün), und der nächste Versuch folgt nach
  15 Minuten, verdoppelt bis höchstens 6 Stunden (`Retry-After` verlängert).
* **Stündlicher Abruf:** der bestätigte Cursor rückt erst vor, wenn der Abstand geschlossen ist; reicht das Seitenlimit
  (`ubuntu_incremental_pages`, Standard 10) nicht, setzt der nächste Lauf per Offset fort (eine Seite Überlappung), es
  entsteht keine Lücke. Ohne Cursor beginnt die Verfolgung mit der ersten Seite.
* **Anzeige:** Feed-Tabelle zeigt je Release Zeitpunkt, Dateigröße, „importiert“ oder „unverändert (304)“ bzw. den Fehler
  samt Statuscode und `Retry-After`, nächsten Versuch sowie für den stündlichen Abruf Seitengröße, Fehler, nächsten Versuch
  und einen Hinweis bei dauerhaftem 503/504. „Aktuell“ erscheint nur bei „vollständig“, ohne dauerhaften Ausfall des
  stündlichen Abrufs (ab drei Fehlläufen in Folge „unvollständig“) und nur, wenn der stündliche Abruf zuletzt erfolgreich
  war und höchstens drei Intervalle zurückliegt (nie erfolgreich = „unvollständig“). Ein laufender Abruf ändert den Zustand
  nicht; er hängt nur an den gespeicherten Zeitstempeln.
* **Hängende Läufe:** steht ein Lauf länger als Anfrage-Timeout (`request_timeout_secs`) plus `connect_buffer_secs`
  (Standard 30 s) in „Verbinden“, endet er als fehlgeschlagen mit „Zeitüberschreitung beim Verbinden“; spätere Phasen
  deckt der Fortschrittswächter ab (`stall_timeout_secs`). Beim Serverstart werden zurückgebliebene Läufe sofort als
  „unterbrochen“ beendet, im Betrieb nach 120 s ohne Lebenszeichen.
* **Speicher:** je Release werden die behobenen Kernel-Einträge (einige Zehntausend CVEs) vor dem Speichern im Speicher
  gehalten, die Datei selbst nie.

## Messwerte und parallele Abrufe

* Je Lauf speichert der Server nur Zahlen (Migration 0019): Dauer je Phase, Anzahl der Anfragen, Statuscodes, Wiederholungen,
  Wartezeit durch Backoff und Pausen, Seitengröße sowie je Anfrage Status, Bytes und Millisekunden (höchstens 200). Keine
  Antwortinhalte, keine Adressen. Die Tabelle „CVE-Quellen“ zeigt unter „Details“ den letzten Lauf und den Median der letzten
  zehn abgeschlossenen Läufe; der Stepper warnt, wenn eine Phase länger als das Dreifache ihres Medians (mindestens 10 s) dauert.
* „Alle abrufen“ startet Debian und Ubuntu gleichzeitig (je Quelle weiter höchstens eine Anfrage). Anreicherungsquellen
  (OSV, NVD, KEV) laufen allein, nachdem diese beiden fertig sind. Der Ausfall einer Quelle stoppt die andere nicht.
  OVAL-Importe der Releases laufen nacheinander (höchstens einer, damit unter der Grenze von zwei bleibt).
