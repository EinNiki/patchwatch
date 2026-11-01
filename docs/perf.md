# Performance: Messung, Ursachen, Ergebnis

Gemessen mit Playwright (Chromium headless, 1440×900, ohne CPU-Drosselung, Median aus 3 Läufen) gegen die Entwicklungs-DB
(7 Hosts, 20 758 CVEs, 111 141 Quellenzeilen, 15 335 Host-CVE-Zeilen), Server als Debug-Build (ein Release-Build ist
schneller). Skripte: `scripts/perf.mjs` (Kaltstart, Seitenwechsel, Aktionen), `scripts/fps.mjs` (Bildrate, optional `CPU=4`).
Alle Zahlen in Millisekunden, wenn nicht anders angegeben. „Nutzbar“ = Inhalt da, kein Skeleton mehr.

## 0. Womit wurde die UI gesehen?

Mit `next dev` (Port 3100). Das ist der größte Einzelfaktor, wenn man die UI so benutzt:

| | Dev (`next dev`) | Produktionsbuild |
|---|---|---|
| JavaScript je Seite (übertragen) | **812–823 KB** (18 Dateien) | **176 KB** (12 Dateien) |
| Nutzbar, Kaltstart Hosts / CVEs / Agents / Einstellungen | 815 / 1127 / 655 / 619 | 275 / 1020 / 274 / 271 |
| Seitenwechsel per Klick (Hosts→CVEs …), Reaktion | 320 / 216 / 127 / 181 | 163 / 164 / 78 / 79 |
| Stern: Klick bis Zustand | 84 | 20 |

Der Dev-Server liefert die UI also 1,5–2,5× langsamer. Produktionsbuild starten: `cd web && npm run build && npm run start:prod`
(siehe README, „UI als Produktionsbuild starten“; `start:prod` ersetzt lokal den Reverse-Proxy und reicht auch den
Live-WebSocket durch).

## 1. Ursachen nach Größe (vor den Änderungen)

1. **Dev-Server** (siehe oben): 4,6× mehr JavaScript, Kompilierung pro Route, langsamere Seitenwechsel.
2. **`GET /cves?limit=100`: 200 ms und 159 KB.** `EXPLAIN ANALYZE`: Die Abfrage aggregierte die Host-Zähler über **alle** 20 758
   CVEs (Hash-Join mit `host_cve_status`, Sortierung auf Platte, 2× ~15 MB `external merge`) und wendete das `LIMIT` erst danach an
   (189 ms). Dazu 1,6 KB je Zeile, meist die volle Beschreibung. Folge: CVEs-Seite brauchte 1020 ms bis „nutzbar“.
3. **View Transition bei jedem Seitenwechsel**: `<ViewTransition>` hielt die DOM-Aktualisierung bis zum Schnappschuss zurück.
   Messung ohne Transition (`NOVT=1`): Agents 131→27, Einstellungen 76→30, Hosts 77→32, CVEs 150→115 ms (Prod-Build).
4. **100 Tabellenzeilen in einem Task**: ~110 ms Scripting, Long Task 91–106 ms beim Aufbau der CVE-Seite (Prod), im Dev-Build 321 ms.
5. **Doppelte Anfragen**: Shell und Seite fragten `/feeds` und `/notifications` getrennt, beim Laden 6–8 Anfragen statt 4–5
   (Dev: 12–15 mit Strict Mode); jeder Seitenaufruf lud auch frische Daten erneut.
6. **Filtern**: jede Eingabe ersetzte die Tabelle durch ein Skeleton (leerer Bildschirm, Layout springt), 300 ms Debounce.
7. **Live-Ereignisse** luden bei jedem Ereignis die komplette Liste (Hosts, CVEs) neu.
8. Kleinere Posten: pro CVE-Zeile ein eigener `useApi`-Hook (100 Abonnements), keine Komprimierung zwischen `next dev` und
   Server (im Betrieb komprimiert Caddy: `/cves` 73 KB → 9 KB mit Brotli).

Keine große Abhängigkeit im Bundle: außer React und Next.js nur Schriften; Seitencode je Route < 35 KB gzip.
Schriften: `@fontsource` mit `font-display: swap`, nur 4 Schnitte (400/600 Atkinson, 400/500 Plex Mono) und Unicode-Ranges.

## 2. Änderungen

- **Server** (`perf(server)`): Liste wählt zuerst die Seite (Filter, Sortierung, `LIMIT`) und bildet Zähler/KEV-Flag nur für
  diese Zeilen (`LATERAL`); Beschreibung in der Liste auf 300 Zeichen gekürzt (Detail liefert sie voll, Volltext-Suche
  durchsucht weiter alles); Filter werden als Konstanten statt als OR-Zweige mit Parametern in die Abfrage geschrieben
  (generischer Plan: „Debian offen“ 0,5 s → 0,07 s); CVE-ID-Suche sucht nur in den IDs. Migration `0006_perf_indexes.sql`
  (nur Indizes: `host_cve_status(cve_id)`, `cves(updated_at DESC, id DESC)`).
- **Web** (`perf(web)`): `useApi` fasst gleichzeitige Anfragen desselben Pfads zusammen, lädt Daten jünger als 5 s beim
  Einhängen nicht neu und lässt Intervallabrufe aus, solange der Cache frisch ist; Live-Ereignisse werden 400 ms gebündelt,
  in der Host-Liste wird nur die betroffene Zeile nachgeladen (`/hosts/{id}`); CVE-Zeilen sind `memo`, die ersten 30 Zeilen
  erscheinen sofort, der Rest in kleinen Schritten; beim Filtern bleibt die alte Liste (abgedunkelt, `aria-busy`) stehen, Debounce 150 ms.
- **Bewegung** (`style(web)`): Seitenwechsel ohne View Transition (CSS-Einblenden 180 ms, sofort sichtbar), Tabellenzeilen
  blenden ein, Stern-Puls, eigene Checkbox mit weichem Haken, Auf-/Zuklappen von `details`; alles nur `opacity`/`transform`,
  Tokens `--dur-1/2`, `--ease-out`, bei `prefers-reduced-motion` nur 80 ms Einblenden ohne Bewegung.

## 3. Ergebnis (nachher)

Server (curl, Median, Debug-Build):

| Endpunkt | vorher | nachher |
|---|---|---|
| `GET /cves?limit=100` | 200 ms / 159 KB | **44 ms / 73 KB** (Brotli über Caddy/`start:prod`: 9 KB) |
| `GET /cves?limit=100&releases=all` | 179 ms / 211 KB | 49 ms / 123 KB |
| `GET /cves?…&debian=open` | nicht gemessen | 75 ms |
| `GET /cves?…&q=kernel` (Volltext) | nicht gemessen | **429 ms** (bleibt langsam, siehe unten) |
| `GET /cves/{id}` | 16 ms / 44 KB | 21 ms / 44 KB |
| `GET /hosts` / `/feeds` / `/notifications` / `/settings` | 14 / 5 / 2,4 / 6 ms | 7 / 4 / 2,6 / 5 ms |

Browser, Produktionsbuild (vorher → nachher):

| | vorher | nachher |
|---|---|---|
| Nutzbar Hosts / CVEs / Agents / Einstellungen | 275 / 1020 / 274 / 271 | **268 / 395 / 270 / 241** |
| API-Anfragen beim Laden (Hosts/CVEs/Agents/Einst.) | 8 / 8 / 7 / 6 | **5 / 5 / 5 / 4** |
| API-Daten CVEs-Seite | 71 KB | 20 KB |
| Seitenwechsel, Reaktion CVEs / Agents / Einst. / Hosts | 163 / 164 / 78 / 79 | **49 / 29 / 30 / 30** |
| Long Tasks > 50 ms beim Laden (CVEs, Max) | 2 (91) | 0 (50) |
| Stern, Klick bis Zustand | 20 | 22 (unverändert, schon schnell) |
| Dialog öffnen | 11 | 8 |
| Filter: Tippen bis neue Liste | nicht messbar (Messfehler im ersten Lauf) | 233 |

Browser, `next dev` (vorher → nachher):

| | vorher | nachher |
|---|---|---|
| Nutzbar Hosts / CVEs / Agents / Einstellungen | 815 / 1127 / 655 / 619 | 843 / 752 / 641 / 599 |
| API-Anfragen beim Laden | 15 / 15 / 13 / 12 | 6 / 6 / 6 / 5 |
| Seitenwechsel, Reaktion CVEs / Agents / Einst. / Hosts | 320 / 216 / 127 / 181 | 171 / 71 / 67 / 99 |
| Stern | 84 | 48 |
| Filter | nicht messbar | 634 |

Bildrate (`scripts/fps.mjs`, Produktionsbuild, **1920 px, CPU 4× gedrosselt**; vorher nicht gemessen):

| Aktion | Frames | p50 | p95 | max | > 50 ms |
|---|---|---|---|---|---|
| Navigation Hosts→CVEs | 58 | 16,7 | 33,4 | 99,9 | 1 |
| Scrollen CVE-Liste (100 Zeilen) | 116 | 16,7 | 50 | 66,7 | 1 |
| Stern umschalten | 48 | 16,7 | 83,2 | 100,1 | 5 |
| Navigation CVEs→Agents | 57 | 16,7 | 50 | 66,7 | 1 |
| Dialog öffnen/schließen | 57 | 16,7 | 16,8 | 50 | 0 |
| Navigation Agents→Hosts / →Einstellungen | 55 / 56 | 16,7 | 16,8 | 66,6 / 49,9 | 1 / 0 |

Median überall 60 fps; einzelne Ausreißer bei 4× Drosselung (Stern: Scripting ~16 ms + Layout/Paint, im Trace ein
Task von 79 ms gedrosselt ≈ 20 ms real).

## 4. Was bleibt langsam

- **Volltextsuche** in Beschreibungen: ~0,4 s (sequenzieller Scan über 20 758 Texte). Abhilfe wäre ein Trigram-Index
  (`pg_trgm`) oder `tsvector`; bewusst nicht gebaut (Erweiterung, Plattenplatz, Datenänderung). Die Suche nach einer CVE-ID ist schnell (18 ms).
- **`releases=all`** liefert alle Release-Chips (123 KB je 100 Zeilen).
- **`next dev`** bleibt langsamer als der Produktionsbuild (Kompilierung, 800 KB JS), unabhängig von allen Änderungen.
- Dev: Seitenwechsel zu den CVEs ~170 ms, weil dort 100 Zeilen im ungebündelten Build gerendert werden.
- Nicht geprüft: echtes Gerät, andere Browser (Firefox, Safari), Verbindung über Netzwerk mit Latenz, größere Datenmengen
  (viele Hosts: die Host-Liste ist nicht virtualisiert; bei 7 Hosts gibt es nichts zu virtualisieren), Release-Build des Servers.
