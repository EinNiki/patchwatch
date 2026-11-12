# Nachtlauf 2026-11-12: Sicherheit (Phase 7)

Gezielte Prüfung des Bereichs seit dem Audit-Commit 687840b, **nur durch Lesen des Codes** (zwei Opus-Agenten,
keine Ausführung, keine Tests). Das ist keine Vollprüfung und ersetzt den unabhängigen Opus-Audit in frischer
Sitzung nicht. Nichts wurde geändert; alle Funde sind offen.

## Zusammenfassung

| Schweregrad | Anzahl | |
|---|---|---|
| kritisch | 0 | |
| hoch | 0 | |
| mittel | 3 | M1 NVD-Schlüssel folgt geänderter Spiegel-URL, M2 `refresh?wait=true` umgeht Sperren, M3 install.sh unsigniert |
| niedrig | 18 | siehe Teil 1 (F2 bis F6) und Teil 2 |

(Teil 1 F7 und Teil 2 Fund 1 sind derselbe Fund M2 und einmal gezählt.)

- **M1** `server/src/routes/feeds.rs:669-676`: Die Adresse einer Quelle lässt sich ändern, ohne dass das gespeicherte
  Geheimnis verworfen wird; der NVD-Schlüssel geht dann an die neue Adresse (auch `http://`). Altbestand vor 687840b.
  Fix: Geheimnis beim Ändern der Adresse verwerfen oder neu verlangen, nur `https://` für Quellen mit Schlüssel.
- **M2** `server/src/routes/feeds.rs:906, 968-990`: `POST /feeds/refresh?wait=true` ruft `refresh_all` ohne
  Mindestabstand, Backoff-Bestätigung und Lauf-Protokoll auf. Vom Dirigenten am Code nachgelesen.
  Fix: den Wartepfad durch dieselbe Sperrprüfung führen oder entfernen.
- **M3** `web/src/lib/agentCommands.ts:5`, `.github/workflows/release.yml:37-41`: `install.sh` selbst ist nicht
  signiert; der angezeigte Befehl führt es mit sudo aus, minisign schützt die Erstinstallation damit nicht.
  Fix: Skript mit signieren und im Befehl vor dem Ausführen prüfen (oder Prüfsumme im Befehl anzeigen).

## Ergänzende Prüfungen des Dirigenten

- Geheimnisse in der Git-Historie (139 Commits, alle Branches, hinzugefügte Zeilen; Muster: private Schlüssel,
  GitHub-, AWS-, Slack-Tokens, `pw_`-Tokens, minisign-Schlüssel, `password|secret|token|api_key = "…"`): keine echten
  Treffer. Alle Treffer sind Testwerte in Rust-Tests und Fixtures bzw. `integrity`-Hashes der Lockdatei. Keine
  `.env`, Schlüssel- oder Dump-Dateien in der Historie.
- `npm audit` (web): 8 Meldungen der Stufe moderate, alle in der Lint-Werkzeugkette (typescript-eslint,
  eslint-config-next, minimatch), keine in Laufzeit-Abhängigkeiten. Nicht geändert.
- `cargo audit`: nicht installiert, nicht geprüft (keine Installation größerer Werkzeuge).
- Vom Modell abgelehnte Prüfpunkte: keine.

---

# Security-Review Teil 1: Avatar, OVAL/Debian-Massenimport, Quellenverwaltung

- Repo: `/home/claude/patchwatch-night`, Branch `overnight/2026-11-12`, HEAD `e9d1608`
- Umfang: `git diff 687840b..HEAD -- server/` plus `web/src` (Avatar). Nur gelesen, nichts gebaut oder ausgeführt, kein Netzwerk.
- "Altbestand" heißt: Der Code war schon zum Audit-Commit 687840b so (dort unverändert). Er steht hier, weil der Auftrag die Stelle ausdrücklich nennt. Er ist evtl. bereits bewusst akzeptiert.
- Nicht als Fund gewertet (Vorgabe): ungeprüfte OIDC-Signatur, keine Bildbibliothek im Server, `eval.rs`.

## Übersicht

| Schweregrad | Anzahl |
|---|---|
| kritisch | 0 |
| hoch | 0 |
| mittel | 1 |
| niedrig | 6 |

---

## Funde

### F1: NVD-Schlüssel geht an eine neu gesetzte Spiegel-URL, ohne dass er neu eingegeben werden muss (write-only umgehbar)
- **Datei:Zeile:** `server/src/routes/feeds.rs:669-676` (base_url-Update), dazu `server/src/cve/sources.rs:60-62` (AAD nur ID), `server/src/cve/sources.rs:304-309`, `server/src/cve/nvd.rs:192-195`
- **Schweregrad:** mittel (Altbestand, vor 687840b)
- **Beleg:** `update` setzt die Adresse unabhängig vom Geheimnis:
  ```rust
  } else if let Some(u) = &b.base_url {
      sqlx::query("UPDATE cve_sources SET base_url = $2, updated_at = now() WHERE id = $1")
  ```
  Das gespeicherte Geheimnis bleibt erhalten. `build_one` entschlüsselt es (`decrypt_secret(state, id, blob)`, AAD `cve_source:{id}`, die URL ist nicht Teil der AAD). `Nvd` sendet es dann als `r.header("apiKey", k)` an `self.base`, also an die neue Adresse. `check_base_url` lässt jede öffentliche Adresse zu und über `parse_url` auch `http://`. Wer eine Admin-Sitzung hat (oder eine gestohlene Sitzung samt CSRF-Token), setzt die URL auf einen eigenen Host und bekommt den Schlüssel beim nächsten Lauf, bei `http://` sogar im Klartext. Damit ist "write-only" ausgehebelt.
- **Fix:** Wird `base_url` einer Quelle mit Geheimnis geändert, das Geheimnis verwerfen oder im selben Request neu verlangen (alternativ die normalisierte base_url in die AAD aufnehmen); für Quellen mit Schlüssel nur `https://` zulassen.

### F2: Weiterleitungen beim OVAL-Download: nur der Host wird verglichen, Schema und Port nicht (Downgrade auf http möglich)
- **Datei:Zeile:** `server/src/cve/oval.rs:454-464`
- **Schweregrad:** niedrig
- **Beleg:**
  ```rust
  let same_host = attempt.previous().first()
      .is_some_and(|first| first.host_str() == attempt.url().host_str());
  if same_host && attempt.previous().len() < 3 { attempt.follow() } ...
  ```
  `host_str()` enthält weder Schema noch Port. Leitet `https://security-metadata.canonical.com/...` auf `http://security-metadata.canonical.com/...` weiter (oder auf einen anderen Port), folgt der Client. Auf diesem Klartext-Abschnitt könnte ein Angreifer im Netz OVAL-Daten einschleusen und damit falsche "behoben"-Einträge erzeugen. Voraussetzung ist, dass die Gegenseite selbst so weiterleitet. In TLS kann ein Angreifer im Netz keinen Redirect einschleusen.
- **Fix:** Nur folgen, wenn Schema und Port der Ausgangs-URL gleich bleiben (mindestens `attempt.url().scheme() == "https"`, sobald die Ausgangs-URL https ist).

### F3: Debian-Tracker und Ubuntu-API laufen über den gemeinsamen Client mit Standard-Redirects (beliebiger Host, auch http) und Umgebungs-Proxy
- **Datei:Zeile:** `server/src/state.rs:33-40`, `server/src/cve/refresh.rs:283` (`src.fetch(&state.http, ...)`), `server/src/cve/debian.rs:217`
- **Schweregrad:** niedrig (Client ist Altbestand; Debian-Pfad und Ubuntu-Stundenabruf wurden seit dem Audit geändert)
- **Beleg:** `reqwest::Client::builder().timeout(...).user_agent(...).build()` setzt keine `redirect(...)`-Policy. Es gilt reqwests Standard: bis zu 10 Hops auf jeden Host, ohne Downgrade-Schutz, und `HTTP(S)_PROXY` wird beachtet. Der Massenimport (`bulk_client`) beschränkt Weiterleitungen dagegen bewusst auf denselben Host. Der 200-MiB-Debian-Abruf hat diese Einschränkung nicht. Die URLs stammen aus der Betreiber-Konfiguration, daher kein SSRF, aber der Schutz der Datenintegrität ist hier schwächer als beim OVAL-Pfad.
- **Fix:** Für Debian und Ubuntu einen eigenen Client mit derselben (nach F2 verschärften) Redirect-Policy wie `bulk_client` verwenden.

### F4: OVAL-Beschreibung und Größe einzelner XML-Ereignisse nicht hart begrenzt
- **Datei:Zeile:** `server/src/cve/oval.rs:216`, `:221`, `:255`; Grenze `server/src/config.rs:180`
- **Schweregrad:** niedrig (setzt eine kompromittierte Quelle oder einen falsch konfigurierten Spiegel voraus)
- **Beleg:** `Event::Text(t) if in_desc && desc.len() < 4000` prüft *vor* dem Anhängen. Ein einzelnes Text-Ereignis kann deshalb beliebig groß sein. `Event::GeneralRef(r) if in_desc` hat gar keine Längenprüfung (jedes `&amp;` hängt 1 Byte an). Beim Übernehmen wird nicht gekürzt (`description: Some(desc.trim().to_owned())`), anders als bei Debian (`truncate(d.trim(), 2000)`, `debian.rs:171`). Außerdem puffert `read_event_into(&mut buf)` ein einzelnes Ereignis (Text oder Attribut) vollständig. Die einzige Grenze ist `ubuntu_oval_max_xml_bytes` = 1 GiB, obwohl laut Doku rund 240 MB realistisch sind. So können Beschreibungen von mehreren hundert MB in die DB gelangen, und der Speicher kann kurzzeitig stark anwachsen.
- **Fix:** Die Beschreibung beim Übernehmen mit `truncate(…, 4000)` kürzen, `GeneralRef` nur unterhalb der Grenze anhängen und `max_xml_bytes` näher an die reale Größe setzen (z. B. 400 MiB), optional Ereignisse über 1 MiB als Formatfehler abbrechen.

### F5: Avatar-Prüfung erlaubt "harmlose" Chunks in beliebiger Länge und Anzahl (Daten schmuggelbar); ICCP-Ankündigung entgegen dem Kommentar nicht geprüft
- **Datei:Zeile:** `server/src/avatar.rs:93-94` (PNG), `:140` (ALPH), `:141-142` (ICCP)
- **Schweregrad:** niedrig
- **Beleg:** `b"PLTE" | b"tRNS" | b"sRGB" | b"gAMA" | b"cHRM" | b"pHYs" => {}` nimmt jede Länge an, und das beliebig oft (z. B. `pHYs` mit 60 KB beliebiger Bytes und korrekter CRC). `iCCP` darf mehrfach vorkommen (je ≤ 4 KB). Bei WebP ist `b"ALPH" => {}` unbegrenzt. `b"ICCP" if !bitstream && len <= MAX_ICC && dims.is_some()` prüft nur, ob VP8X vorhanden ist. Das ICC-Bit `0x20` wird nicht geprüft, obwohl der Kommentar in Z. 141 "muss im VP8X-Kopf angekündigt sein" sagt. Folge: Das Ziel "ohne Metadaten" ist nicht vollständig durchgesetzt. Keine XSS-Gefahr, denn das Bild geht nur an den Eigentümer, mit festem Content-Type, `nosniff` und `CSP default-src 'none'`.
- **Fix:** Feste Längen und höchstens ein Vorkommen erzwingen (sRGB=1, gAMA=4, cHRM=32, pHYs=9, PLTE ≤ 768 und durch 3 teilbar, tRNS ≤ 256, iCCP/ICCP einmal), ICCP nur bei gesetztem VP8X-Bit `0x20` annehmen, ALPH nur einmal und nur nach VP8X.

### F6: Quellenname: Unicode-Format- und Trennzeichen (Bidi-Override, Zero-Width, U+2028) werden angenommen
- **Datei:Zeile:** `server/src/routes/feeds.rs:474`
- **Schweregrad:** niedrig (Altbestand)
- **Beleg:** `label.chars().any(char::is_control)` erfasst nur die Kategorie Cc. Durch kommen U+202A–U+202E und U+2066–U+2069 (Bidi), U+200B–U+200F und U+FEFF (Format/Zero-Width) sowie U+2028/U+2029 (Zeilen-/Absatztrenner), obwohl die Meldung "keine … Zeilenumbrüche" verspricht. Der eindeutige Index `lower(label)` (`migrations/0005_cve_source_names.sql:27`) lässt sich mit Zero-Width-Zeichen umgehen, z. B. ein zweites "NVD" neben "NVD". In Bestätigungsdialogen ("Quelle „…“ löschen?") wird ein so manipulierter Name falsch dargestellt. HTML ist kein Problem, React escaped (`FeedSources.tsx:420`, `:567`).
- **Fix:** Zusätzlich Zeichen der Kategorien Cf, Zl und Zp ablehnen (oder den Namen vor Prüfung und Unique-Vergleich NFKC-normalisieren).

### F7: `POST /feeds/refresh?wait=true` umgeht die neuen manuellen Sperren (Mindestabstand/Backoff)
- **Datei:Zeile:** `server/src/routes/feeds.rs:900-968` (Gate nur im Zweig `!wait`), `:971-980` (`refresh_wait` ruft `refresh_all` ohne `runs::gate`)
- **Schweregrad:** niedrig (Härtung; nur Admin mit CSRF-Token)
- **Beleg:** `run_source` und der asynchrone `refresh` prüfen `manual_gate`/`runs::gate` (seit dem Audit neu). Der synchrone Pfad `refresh_wait` nimmt nur `run_gate.try_write_owned()`. Er kann direkt nacheinander wiederholt werden und erzeugt jedes Mal Ubuntu-API-Seiten- und NVD-Anfragen, auch wenn die Quelle im Backoff steht. Die OVAL-Dateien schützt die eigene `due`-Logik (`ubuntu.rs` in `fetch_hybrid`), Debian ist bedingt (304).
- **Fix:** `runs::gate` auch in `refresh_wait` je Quelle anwenden (oder `wait=true` nur noch mit `confirm` und eigenem Rate-Limit erlauben).

---

## Geprüft und in Ordnung

**Avatar (Server)**
- Magic Bytes: nur PNG-Signatur oder `RIFF….WEBP` (`avatar.rs:50-56`). SVG, GIF und JPEG werden abgelehnt (`avatar.rs:55`, Tests `:308-325`).
- Größe: `DefaultBodyLimit::max(MAX_BYTES + 1024)` an der Route (`routes/mod.rs:57-65`), `data.len() > MAX_BYTES` (`avatar.rs:47`) und die DB-Constraint `octet_length(avatar) <= 65536` (`migrations/0018_admin_avatar.sql`).
- Abmessungen: PNG über das IHDR an erster Stelle mit `len == 13` (`avatar.rs:80-88`). WebP über VP8X, VP8 und VP8L, die übereinstimmen müssen (`avatar.rs:138`, `:147-152`, `:159-164`, `:172-176`).
- PNG-Chunks: `checked_add` für `end`, `end > d.len()`, CRC über Typ und Daten, nur Whitelist, IEND mit `len == 0`, mindestens ein IDAT und `end == d.len()` (keine Anhängsel) (`avatar.rs:65-104`). Alle Indizes liegen in den Grenzen; die Schleife kommt je Runde um mindestens 12 Byte voran.
- WebP-Chunks: `riff_len + 8 == d.len()` exakt, `pos + 8`-Grenze, `checked_add`, Padding-Byte innerhalb der Datei, Längenprüfung vor jedem Indexzugriff (Kurzschluss in `:135`, `:144`, `:156`), VP8X nur als erster Chunk, Flag-Maske `0x0E` = EXIF|XMP|Animation (korrekt nach RIFF/WebP-Spezifikation), ANIM/ANMF/EXIF/XMP über die Whitelist abgelehnt (`avatar.rs:108-177`). Überläufe wären nur auf 32-Bit-Zielen denkbar; gebaut wird nur x86_64/aarch64 (`server/Dockerfile`, `.github/workflows/release.yml`).
- Antwort: fester Content-Type aus einer festen Liste (`auth.rs:238-242`), `nosniff`, `Cache-Control: private, max-age=300`, `CSP: default-src 'none'`, `Content-Disposition: inline`, `CORP: same-origin` (`auth.rs:198-223`).
- Auth/CSRF: GET mit `Admin`, PUT und DELETE mit `CsrfAdmin` (`auth.rs:226-229`, `:250-255`, `:292-295`; CSRF-Prüfung `extract.rs:71-83`). Die Auth läuft vor dem Lesen des Bodys (Parts-Extractor vor `Bytes`).
- Rate-Limit: PUT 10/10 min je Benutzer, vor der Prüfung (`auth.rs:256-264`), dazu global 600/min je IP (`routes/mod.rs:35-36`). DELETE hat nur das globale Limit, das reicht.
- Der angegebene Content-Type muss zum Inhalt passen (`auth.rs:267-281`). GET liefert nur das eigene Bild (`WHERE username = $1`).

**Avatar (Web)**
- Eingebunden nur per `<img src={`/api/v1/auth/avatar?v=${version}`}>`; `version` ist eine Zahl aus `/auth/me` (`web/src/components/Avatar.tsx:18-28`). Kein `innerHTML`, keine Daten-URL, keine fremde Quelle. Einziges `dangerouslySetInnerHTML` ist das statische Theme-Skript (`web/src/app/layout.tsx:22,28`).
- Vorschau über `createImageBitmap` und Canvas aus der lokalen Datei, Upload als neu kodierter Blob (`AvatarForm.tsx:13-24`, `:57-61`, `:88`). Vorprüfung an den Bytes (`web/src/lib/avatar.ts:45-58`). Content-Type kommt aus dem Blob, CSRF-Header ist gesetzt (`web/src/lib/api.ts:36-39`).

**OVAL- und Debian-Massenimport**
- Komprimierte Bytes: Vorprüfung per `Content-Length` und Zählung beim Streamen *vor* der Weitergabe an den Parser (`oval.rs:359-361`, `:399-402`). Läuft reqwest-gzip automatisch mit, wird nach dem Entpacken gezählt, das ist ebenfalls begrenzt.
- Entpackte Bytes: `Capped` zwischen bz2-Decoder und XML-Reader; zu viel ist ein Fehler und wird nie still abgeschnitten (Probe-Read bei `left == 0`) (`oval.rs:59-83`, `:162-166`). Debian: Zählung nach dem gzip-Entpacken durch reqwest (`http.rs:109-128`, Limit 200 MiB `config.rs:174`).
- Speicher: Streaming über einen beschränkten Kanal (8 Blöcke, Rückstau) und einen blockierenden Parser-Thread (`oval.rs:374-393`). Ausnahme siehe F4.
- XML: quick-xml ohne DTD-Verarbeitung. `DocType` wird ignoriert, `GeneralRef` nur für die fünf vordefinierten Entitäten, alles andere wird `""` (`oval.rs:221-231`). Attribute über `unescape_value().ok()`, unbekannte Entität ergibt `None` (`oval.rs:133-138`). Damit kein XXE und kein Billion-Laughs.
- Zeitlimits: OVAL insgesamt 900 s über `tokio::time::timeout` (`oval.rs:300-311`, `config.rs:181`), Verbindungsaufbau 20 s (`oval.rs:467`). Debian 120 s je Anfrage inkl. Body (`http.rs:69`, `debian.rs:30`). Ubuntu-Seiten 90 s. Wird ein Zeitlimit überschritten, wird der Kanal geschlossen und der Parser-Thread endet.
- Temp-Dateien: keine (`grep tempfile|std::fs|File::create` in `server/src` findet nur das Lesen der Konfiguration, `config.rs:270`).
- Abgeschnittene Daten: OVAL erzeugt nur `Fixed` und nur beim `End` eines vollständigen `<definition>` (`oval.rs:236-262`), nie `NotAffected`. Fehlt `</definitions>`, gibt es `Err` (`oval.rs:269-274`). Ein Netzfehler oder eine zu große Datei hat Vorrang vor einem eventuell erfolgreichen Parse (`oval.rs:441-443`), bei einem Netzfehler bekommt der Parser zusätzlich einen expliziten I/O-Fehler (`oval.rs:412-420`). Ein Importfehler verändert keine gespeicherten Daten (`ubuntu.rs:654`). Debian: Abgeschnittenes JSON ergibt einen serde-Fehler, ohne `linux`-Eintrag einen Formatfehler (`debian.rs:189-199`). `"resolved"` ohne gültige Version wird `Unknown`, nie grün (`debian.rs:89-98`).
- Fix-Version aus OVAL: strenger Zeichensatz und Länge ≤ 100, Paket muss mit `linux` beginnen, Release ist exakt vorangestellt (`oval.rs:115-131`). Eine ungültige Version wird in der Bewertung zu `Unknown` (`eval.rs:158-165`). Release-Namen in der URL nur `[a-z0-9]{1,32}` (`oval.rs:43-49`).
- Redirects im Massenimport: höchstens 3, nur auf denselben Host; ein gestoppter Redirect wird zu `FeedError::Http(3xx)` (`oval.rs:454-464`). Einschränkung siehe F2.

**Quellenverwaltung, SSRF und Geheimnisse**
- Name: getrimmt, 1–40 Zeichen, keine Cc-Steuerzeichen (`feeds.rs:466-480`); eindeutig per `lower(label)`. In der UI überall React-escaped. Einschränkung siehe F6.
- Ökosystem: Whitelist der Zeichen, ≤ 40 (`feeds.rs:482-498`). Typ: nur bekannte Typen (`feeds.rs:548-552`). `deny_unknown_fields` an beiden Bodys (`feeds.rs:424`, `:436`).
- URL: `parse_url` erlaubt nur http(s), ohne Zugangsdaten, ohne Query und Fragment, ≤ 2048 Zeichen, ohne Steuerzeichen (`ssrf.rs:40-62`). Spiegel-URLs nur für osv/nvd/cisa_kev (`sources.rs:37-39`, `feeds.rs:504-509`).
- SSRF: Alle aufgelösten Adressen werden geprüft (`ssrf.rs:175-210`). Loopback, Link-Local (169.254/16, fe80::/10), 0/8, Multicast/Broadcast und `fd00:ec2::` sind *vor* der Allowlist gesperrt (`ssrf.rs:84-109`, `:147-156`), auch eingebettet in IPv4-mapped/-compatible, NAT64 und 6to4 (`ssrf.rs:65-82`). Private Ziele nur bei exaktem Host-Treffer. Gepinnt per `resolve_to_addrs`, kein Redirect, `no_proxy()` (`ssrf.rs:216-233`). Beim Bau jeder Quelle wird neu geprüft und neu gepinnt (`sources.rs:291-299`). Damit ist DNS-Rebinding abgedeckt.
- Verschlüsselung: XChaCha20-Poly1305, 24-Byte-Nonce aus `OsRng` je Verschlüsselung, Format `nonce||ct+tag`, Längenprüfung vor dem Entschlüsseln (`notify/crypto.rs:14-50`). Schlüssel: genau 32 Byte Base64 (`config.rs:69-80`), kein KDF nötig, da Zufallsschlüssel; `Debug` geschwärzt (`config.rs:97`). AAD-Namensräume getrennt: Kanäle = feste `KINDS` (`channels.rs:16-18`), Quellen = `cve_source:{id}` (`sources.rs:60-62`), OIDC = `oidc-client-secret` (`oidc.rs:25`), keine Überschneidung möglich. Neue IDs mit 40 Bit Zufall (`sources.rs:65-73`).
- Write-only: Die API liefert nur `secret_set` (`sources.rs:83-85`, `:130`; `feeds.rs:392`), `create` liefert nur `id` und `label`. Beim Löschen wird das Geheimnis sofort auf NULL gesetzt (`feeds.rs:719`). Fehlertexte enthalten weder Geheimnis noch URL (`e.without_url()`, `http.rs:73`, `:115`; `nvd.rs:6`). Logs enthalten nur ID und FeedError-Text. Einschränkung siehe F1.
- NVD ohne Spiegel: eigener Client ohne Redirects; gibt es mit Schlüssel keinen Client, ist das ein Fehler und kein Rückfall auf den gemeinsamen Client (`nvd.rs:46-53`, `:169-173`).

## Nicht prüfbar ohne Ausführung

- Verhalten von `bzip2 0.6` (`BzDecoder`) bei abgeschnittenem Eingang (Fehler oder stilles `Ok(0)`). Abgesichert ist das ohnehin durch die `</definitions>`-Prüfung und den Vorrang von `net_err`; der Crate-Quelltext wurde nicht gelesen.
- quick-xml 0.38 im Detail: dass es intern wirklich keine DTD-/Entity-Expansion gibt, `unescape_value` bei unbekannter Entität, `check_end_names`-Standard, Verhalten bei EOF mit offenen Elementen. Bewertet wurde nach Bibliotheksdesign, nicht am Crate-Code.
- reqwest 0.12: ob gzip auf `bulk_client` aktiv ist und `content_length()` dann `None` liefert; ob `resolve_to_addrs` den Port der URL nutzt und das Pinning in jedem Fall greift.
- Tatsächliche Antwort-Header hinter Caddy (`deploy/Caddyfile`, `encode zstd gzip`) und das Verhalten von Browsern bei geschmuggelten PNG-/WebP-Chunks (F5).
- Laufzeit- und Speicherverhalten bei einer bz2-Bombe bis 1 GiB innerhalb von 900 s; die Tests (`server/tests/avatar.rs`, `server/tests/cve.rs`) wurden nicht ausgeführt.
- Ob Canonical oder Debian jemals auf http oder einen fremden Host weiterleiten (F2/F3); dafür wäre Netzwerkzugriff nötig.

## Abgelehnt

- Keine Prüfpunkte abgelehnt.

## Auffälliges (kein eigener Fund)

- `ubuntu_oval_url` (sowie `nvd_url`, `kev_url`) fehlt in der Schema-Prüfung der Konfiguration (`config.rs:507-515` prüft nur ubuntu/debian/osv). `http://` ist per Betreiber-Konfiguration möglich, was F2 verschärfen würde.
- `bulk_client()` fällt mit `.unwrap_or_default()` auf `Client::default()` zurück (`oval.rs:474`). Das wären Standard-Redirects auf beliebige Hosts, ohne Connect-Timeout. Vermutung: praktisch nicht erreichbar, weil der Standard-Client dann ebenfalls scheitern (panic) würde. Sauberer wäre ein Fehler.
- `purge_deleted` entfernt den neuen Schlüssel `schedule.feeds.bulk_interval_minutes.{id}` nicht (`sources.rs:162-165` vs. `schedule.rs` `bulk_key`). Das betrifft nur die Datenhygiene.
- Kommentar `debian.rs:3` sagt "Geparst wird streamend", der Body liegt aber vollständig im Speicher (bis 200 MiB, `http.rs:106-127`). Funktional ist das begrenzt; es fällt nur für die Speicherplanung auf.
- `bulk_client` nutzt Umgebungs-Proxys (kein `no_proxy()`). Bei der festen Betreiber-URL ist das unkritisch, unterscheidet sich aber vom SSRF-Client.


---

# Security-Review Teil 2: Code seit Audit-Commit 687840b

Stand: Branch `overnight/2026-11-12`, Worktree `/home/claude/patchwatch-night`, HEAD `e9d1608`.
Methode: nur lesen (Dateien, grep, `git diff/show/log`). Nichts gebaut, getestet oder ausgeführt.
Feststehende Entscheidungen (nur `report_requested` an den Agent, OIDC-ID-Token-Signatur, `eval.rs`) sind nicht bewertet.

## Übersicht

| Schweregrad | Anzahl |
|---|---|
| kritisch | 0 |
| hoch | 0 |
| mittel | 2 |
| niedrig | 13 |

Vom Modell abgelehnte Prüfpunkte: keine.

---

## Funde

### M1: `POST /feeds/refresh?wait=true` umgeht Mindestabstand, Backoff-Bestätigung und Laufprotokoll
- **Datei:Zeile:** `server/src/routes/feeds.rs:906`, `:968`, `:971-990`; `server/src/cve/refresh.rs:559-577`
- **Schweregrad:** mittel
- **Beleg:** Nur der Zweig ohne `wait` ruft `runs::gate` auf. Mit `wait=true` geht es direkt zu `refresh_wait`, dann zu `refresh::refresh_all`, und das ruft `refresh_source` für jede eingeschaltete Quelle auf. Dabei gibt es keinen Mindestabstand von 60 s, keine Prüfung auf `next_attempt_at`/Backoff, keine Bestätigung, keine Regel „1 Versuch je 5 min“, und es wird keine `feed_runs`-Zeile angelegt. Weil keine Zeile entsteht, sieht der nächste `gate`-Aufruf (`runs.rs:704-714`, `max(created_at) FROM feed_runs`) diesen Abruf auch nicht. Einzige Sperre ist `run_gate.try_write_owned()` (409 nur während eines laufenden Abrufs). Der Weg ist nur für Admins mit CSRF-Token offen. Im Code wird er von `scripts/dev-seed.py:96` und den Tests genutzt, die UI nutzt ihn nicht. Ein Skript in einer Schleife kann damit Ubuntu/NVD trotz Backoff dauerhaft anfragen (Gefahr für den API-Schlüssel und für Sperren durch die Gegenseite).
- **Fix:** `wait=true` je Quelle ebenfalls über `runs::gate` und `runs::start` führen (oder nur in Test/Dev-Builds zulassen), damit Rate-Limit, Backoff-Bestätigung und Protokoll für jeden manuellen Abruf gelten.

### M2: Das Installer-Skript selbst ist nicht signiert, der angezeigte Befehl führt es ungeprüft mit `sudo` aus
- **Datei:Zeile:** `web/src/lib/agentCommands.ts:5`, `web/src/app/(app)/agents/page.tsx:30-35`, `.github/workflows/release.yml:37-41` (install.sh wird nur mit `.sha256` veröffentlicht), `:56-58` (minisign signiert nur das Binary)
- **Schweregrad:** mittel
- **Beleg:** `curl -fsSL -o install.sh ${releaseBase}/install.sh && sudo sh install.sh --server-url ${origin}` mit `RELEASE_BASE = "https://github.com/EinNiki/patchwatch/releases/latest/download"`. Der minisign-Schlüssel `PW_PUBKEY` steht *im* Skript (`install.sh:97`). Wer die Release-Assets ersetzen kann, also genau der Angreifer, gegen den die Signatur schützen soll, ersetzt einfach `install.sh` mitsamt Schlüssel und bekommt Root auf jedem neu eingerichteten Host. Die Schutzwirkung von minisign gilt damit nur für `patchwatch-agent-update`, das kein Skript lädt (`install.sh:239-241`), nicht für die Erstinstallation. Die Kommentarzeile `release.yml:43` („ungeprüfte Artefakte gibt es nicht“) trifft auf install.sh nicht zu.
- **Fix:** install.sh ebenfalls mit minisign signieren und im kopierten Befehl vor `sudo sh` die Signatur mit dem öffentlichen Schlüssel prüfen, der in UI/README fest steht (oder ein versioniertes, festgeschriebenes Skript mit Prüfsumme anzeigen statt `latest`).

### N1: TOML-Parserfehler geben die betroffene Zeile von agent.toml wörtlich aus, auch eine `token = …`-Zeile
- **Datei:Zeile:** `agent/src/config.rs:57`; aufgerufen von `agent/src/setcmd.rs:104` (set-token), `agent/src/status.rs:150` (status), `agent/src/main.rs:95` (Dienstlauf); Ausgabe über `main.rs:132` auf stderr/Journal
- **Schweregrad:** niedrig
- **Beleg:** `toml::from_str(text).map_err(|e| AgentError::Config(e.to_string()))`. toml 0.8.23/toml_edit 0.22.27 setzt den Rohtext (`set_raw`), und `Display` schreibt die ganze Zeile (`toml_edit-0.22.27/src/error.rs:96-110`: `writeln!(f, "{content}")`). Beispiele, die die Token-Zeile treffen: `Token = "pw_…"` (unbekanntes Feld, `deny_unknown_fields`), `token = pw_…` ohne Anführungszeichen, `token` doppelt. Betroffen sind alle Nutzer mit Klartext-Token, also genau die Zielgruppe von `--migrate`. Beim Dienst landet die Zeile im Journal. (`config.rs` selbst ist seit dem Audit unverändert, die neuen Befehle `set-token` und `status` nutzen den Weg aber zusätzlich.)
- **Fix:** Bei TOML-Fehlern nur Zeile, Spalte und Fehlerart melden (aus `e.span()` und `e.message()`), nie die Quelltextzeile.

### N2: Der Haupt-Argumentparser gibt unbekannte Argumente wörtlich aus (`--token=pw_…`, `pw_…`)
- **Datei:Zeile:** `agent/src/main.rs:57-61`
- **Schweregrad:** niedrig
- **Beleg:** `other => return Err(AgentError::Config(format!("unbekannte Option {other}\n{USAGE}")))`. `patchwatch-agent --token=pw_… set-token`, `patchwatch-agent pw_…` oder `patchwatch-agent checkin pw_…` schreiben den Token auf stderr. Nur der Parser *hinter* `set-token` vermeidet das (`setcmd.rs:34-35`, `:54-66`). Die Tests (`agent/tests/cli.rs:194-199`) decken nur Argumente nach `set-token` ab. Zu ExecStart oder Journal kommt es nur bei Fehlbedienung.
- **Fix:** Unbekannte Argumente im Hauptparser wie in `setcmd::parse_args` nur nennen, wenn sie dem Muster `--[a-z-]{1,22}` entsprechen, sonst eine generische Meldung ausgeben.

### N3: `--token-file`: Prüfung und Öffnen sind getrennt (TOCTOU), kein `O_NOFOLLOW`
- **Datei:Zeile:** `agent/src/token.rs:104-120`
- **Schweregrad:** niedrig
- **Beleg:** Zuerst `symlink_metadata(path)` mit `is_file()` und Größe (105-115), danach separat `File::open(path)` (116). Wird die Datei dazwischen gegen einen Symlink getauscht, folgt `open` ihm. Ein Tausch gegen eine FIFO lässt `sudo patchwatch-agent set-token` hängen. Dafür braucht der Angreifer Schreibrecht im Ordner der Token-Datei (z. B. wenn ein Benutzer die Datei in seinem eigenen Ordner ablegt und dann `sudo` aufruft). Rechte und Besitzer der Quelldatei werden nicht geprüft und nicht gewarnt.
- **Fix:** Mit `custom_flags(O_NOFOLLOW | O_NONBLOCK)` öffnen und Typ und Größe per `f.metadata()` (fstat) am offenen Handle prüfen.

### N4: Atomares Schreiben setzt Rechte und Besitzer per Pfad (folgt Symlinks), gruppenbeschreibbare Ordner sind erlaubt
- **Datei:Zeile:** `agent/src/token.rs:232-237` (`std::fs::set_permissions(&tmp, …)`, `std::os::unix::fs::chown(&tmp, …)`), `:153` (nur `mode & 0o002` geprüft)
- **Schweregrad:** niedrig
- **Beleg:** Die Temp-Datei wird korrekt mit `create_new(true).mode(0o600)` angelegt (O_CREAT|O_EXCL, folgt keinem Symlink, Modus schon beim Anlegen höchstens 0600). `chmod` und `chown` laufen danach aber über den Pfad und folgen Symlinks. Ersetzt jemand mit Schreibrecht im Zielordner die Temp-Datei zwischen `open` und `chmod/chown` durch einen Symlink, ändert root Modus und Besitzer einer beliebigen Datei, und `rename` legt den Symlink als Token-Datei ab. `check_target` lehnt nur für alle beschreibbare Ordner ab, gruppenbeschreibbare (z. B. `root:adm 0775`) gehen durch. Die Prüfung läuft außerdem vor dem Schreiben (TOCTOU). Standardpfad `/etc/patchwatch` (0755 root) ist nicht betroffen.
- **Fix:** Rechte und Besitzer am offenen Handle setzen (`f.set_permissions(…)`, `std::os::unix::fs::fchown(&f, …)`) und auch gruppenbeschreibbare Ordner ablehnen.

### N5: `--migrate` tut nichts, wenn `token` und `token_file` gleichzeitig gesetzt sind; der Klartext-Token bleibt, die Meldung sagt das Gegenteil
- **Datei:Zeile:** `agent/src/setcmd.rs:107`, `:120-125`; `agent/src/status.rs:157-165`
- **Schweregrad:** niedrig
- **Beleg:** `let inline = cfg.token.is_some() && cfg.token_file.is_none();`. Bei beiden Einträgen ist `inline == false`, `--migrate` meldet „Hinweis: --migrate ist nicht nötig (kein Token in agent.toml).“, schreibt nur die Token-Datei und lässt `token = "pw_…"` im Klartext in der (oft 0644) agent.toml stehen. `status` zeigt in diesem Fall „Datei …“ als Herkunft und warnt nicht vor dem verbliebenen Eintrag.
- **Fix:** Bei `cfg.token.is_some()` immer migrieren bzw. den Eintrag entfernen und in `status` warnen, wenn noch ein `token`-Eintrag in agent.toml steht.

### N6: install.sh überschreibt eine vorhandene Token-Datei nicht atomar, mit alten Rechten bis zum `chmod` und folgt Symlinks
- **Datei:Zeile:** `install.sh:260-264` (identisch in `agent/dist/install.sh`)
- **Schweregrad:** niedrig
- **Beleg:** `( umask 077; printf '%s\n' "$TOKEN" > /etc/patchwatch/token )`, danach `chown` und `chmod 0600`. Die umask gilt nur beim Neuanlegen. Wird mit `--token-file`/`PATCHWATCH_TOKEN` eine bestehende Datei ersetzt, steht der neue Token kurz mit dem alten Modus (z. B. 0644) darin. `>` schneidet ab statt atomar zu ersetzen (ein Abbruch hinterlässt eine leere Datei). `>`, `chown` und `chmod` folgen einem Symlink an dieser Stelle. Weil `/etc/patchwatch` root gehört (0755), ist der praktische Angriffsweg klein.
- **Fix:** Wie `set-token` schreiben: `mktemp /etc/patchwatch/.token.XXXXXX` mit umask 077, `chown`/`chmod` auf die Temp-Datei, dann `mv -f` auf das Ziel, und einen Symlink am Ziel vorher ablehnen.

### N7: install.sh fragt den Token mit Echo ab, wenn `stty -echo` scheitert
- **Datei:Zeile:** `install.sh:71-73`
- **Schweregrad:** niedrig
- **Beleg:** `stty -echo <"$TTY" 2>/dev/null || true`, danach `read -r TOKEN`. Scheitert `stty` (TTY nicht steuerbar, `stty` fehlt), ist der Token beim Tippen sichtbar, obwohl der Prompt „Eingabe bleibt unsichtbar“ verspricht. Ohne `trap` bleibt das Echo nach Strg+C aus. Der Agent bricht in dieser Lage dagegen ab (`token.rs:69-81`).
- **Fix:** Bei fehlgeschlagenem `stty -echo` mit Hinweis auf `--token-file` abbrechen und `trap 'stty echo <"$TTY"' EXIT INT TERM` setzen.

### N8: Suchtext `q` der CVE- und Host-CVE-Listen ohne Längengrenze
- **Datei:Zeile:** `server/src/routes/cves.rs:254-268`, `server/src/routes/hosts.rs:275-286`, `:445-456`
- **Schweregrad:** niedrig
- **Beleg:** Es werden nur Steuerzeichen abgelehnt (cves.rs), in hosts.rs nicht einmal das (NUL fängt `routes/mod.rs:141-152` global ab). Obergrenze ist nur die URI-Grenze von hyper (`MAX_URI_LEN = u16::MAX - 1`, `hyper-1.12.0/src/proto/h1/role.rs:34`), also etwa 64 KB. Daraus wird `ILIKE '%…%'` über `c.description` aller CVEs, in `scope_count` dreimal je Anfrage (`cves.rs:358-369`). *Vermutung (nicht gemessen):* Lange Muster kosten je Anfrage deutlich CPU in Postgres, weil ILIKE das Muster je Zeile neu klein schreibt. Nur für Admins offen, die globale Grenze von 600/min/IP gilt.
- **Fix:** Suchtext auf z. B. 200 Zeichen begrenzen (400 bei mehr) und in hosts.rs ebenfalls Steuerzeichen ablehnen.

### N9: Keine Content-Security-Policy; Schutz-Header fehlen bei `/api`; HSTS nur über Caddy
- **Datei:Zeile:** `web/next.config.ts:19-30`, `deploy/Caddyfile:14-17`; Server ohne Header-Layer (`server/src/routes/mod.rs:110-118`)
- **Schweregrad:** niedrig
- **Beleg:** `next.config.ts` setzt nur `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy` und `Permissions-Policy`. Im Repo setzt außer der Avatar-Antwort (`server/src/routes/auth.rs:211`) niemand eine `Content-Security-Policy`. API-Antworten bekommen nur, was Caddy setzt (HSTS, `-Server`), also kein nosniff/XFO. Ohne den mitgelieferten Caddy (Betrieb direkt über `web:3000`/`server:8080`) gibt es auch kein HSTS. Eine XSS-Senke wurde nicht gefunden (siehe „geprüft“). Die CSP wäre die zweite Verteidigungslinie für die Darstellung fremder Feed-Texte.
- **Fix:** In Caddy (oder `next.config.ts`) eine CSP setzen, etwa `default-src 'self'; script-src 'self' 'sha256-<THEME_SCRIPT>'; connect-src 'self'; img-src 'self' data: blob:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'`. nosniff auch für `/api/*` setzen.

### N10: WebSocket-Origin-Prüfung ignoriert das Schema
- **Datei:Zeile:** `server/src/routes/live.rs:32-35`
- **Schweregrad:** niedrig
- **Beleg:** `(Some((_, o_host)), Some(h)) => o_host == h`. `http://pw.example.org` wird für `Host: pw.example.org` genauso akzeptiert wie `https://…`. Ausnutzbar wäre das nur mit eingeschleustem Inhalt auf der HTTP-Variante derselben Domain (MITM vor dem ersten HSTS-Kontakt). Ob der Browser das `SameSite=Strict`-Cookie dann mitsendet, hängt vom „schemeful same-site“-Verhalten ab (Vermutung, nicht geprüft).
- **Fix:** Wenn `cookie_secure` gesetzt ist, nur `https://`-Origins zulassen (bzw. das Schema gegen `X-Forwarded-Proto` vergleichen).

### N11: WebSocket-Verbindungslimit ist nur global (64); eine einzelne Session kann alle Plätze belegen
- **Datei:Zeile:** `server/src/state.rs:49`, `server/src/routes/live.rs:47-53`
- **Schweregrad:** niedrig
- **Beleg:** `live_slots: Arc::new(tokio::sync::Semaphore::new(64))`, ohne Grenze je Session oder IP. Eine Admin-Session (oder ein hängender Client) mit 64 offenen Sockets nimmt allen anderen die Live-Updates (429). Eine Leerlauf-Trennung nach 75 s gibt es (`live.rs:105-107`), aber nur für Clients, die nicht auf Pings antworten.
- **Fix:** Zusätzlich je `session_hash` (oder IP) auf wenige gleichzeitige Verbindungen begrenzen, z. B. 4.

### N12: Manueller Abruf: Gate-Prüfung und Anlegen des Laufs sind nicht atomar (theoretisch zwei Läufe innerhalb von 60 s)
- **Datei:Zeile:** `server/src/routes/feeds.rs:821-833`, `server/src/cve/runs.rs:381-411`, `:698-747`
- **Schweregrad:** niedrig (theoretisch)
- **Beleg:** Ablauf: Prüfung „läuft schon einer“, dann `gate` (liest `max(created_at)`), dann `INSERT … ON CONFLICT DO NOTHING`, jeweils in eigenen Anweisungen. Der eindeutige Teilindex (`migrations/0017_feed_runs.sql:27`) verhindert zwei *gleichzeitig offene* Läufe zuverlässig (409). Endet der erste Lauf aber, bevor der zweite parallele Request sein INSERT absetzt (z. B. 304 nach wenigen ms), entsteht ein zweiter Lauf, obwohl der Mindestabstand von 60 s gilt. Das Zeitfenster ist sehr klein.
- **Fix:** Gate und INSERT in einer Transaktion mit `pg_advisory_xact_lock(hashtext(source))` ausführen.

### N13: `feed_runs.error` kann Fragmente der Antwortinhalte enthalten (Parser-Fehlertexte)
- **Datei:Zeile:** `server/src/cve/debian.rs:191` (`FeedError::Format(e.to_string())`), `server/src/cve/oval.rs:182`, `server/src/cve/refresh.rs:410/416` und von dort `runs.rs:608-610` (`short(e)`, bis 500 Zeichen)
- **Schweregrad:** niedrig (Vermutung)
- **Beleg:** Der Debian-Parser deserialisiert in typisierte Strukturen (`BTreeMap<String, DebCve>`, `debian.rs:134`). serde-Typfehler lauten z. B. `invalid type: string "…", expected …` und zitieren den Wert aus der Antwort. Auch quick-xml-Fehler nennen Elementnamen bzw. Inhalte. Das sind öffentliche Feed-Daten, keine Schlüssel. Die Migrationen versprechen aber „nie Antwortinhalte“ (`0017_feed_runs.sql:3`). Schlüssel und URLs werden korrekt entfernt (`http.rs:73,115` `without_url()`, NVD-Schlüssel nur im Header, `nvd.rs:44-53`).
- **Fix:** Parserfehler auf feste Texte mit Zeile/Spalte abbilden (z. B. `serde_json::Error::line()/column()/classify()`) statt `e.to_string()` zu übernehmen.

---

## Geprüft und in Ordnung

**1. Agent `set-token` / `status`, install.sh**
- `--token <wert>` und `--token=…` werden ohne Wiedergabe abgelehnt, positionale Argumente ebenso. Unbekannte Optionen werden nur bei Muster `--[a-z-]` genannt: `agent/src/setcmd.rs:34-35`, `:54-66`.
- Eingabe ohne Echo nur an einem TTY; scheitert `stty`, bricht der Agent ab statt mit Echo weiterzumachen: `agent/src/token.rs:69-81`, `:91-101`.
- `--stdin` und Datei lesen höchstens 130 Byte und entfernen genau einen Zeilenumbruch: `token.rs:50-64`. Formatprüfung ohne Wert in der Meldung: `token.rs:23-47`.
- Temp-Datei im selben Ordner, `create_new` (O_CREAT|O_EXCL, folgt keinem Symlink), `mode(0o600)` schon beim Anlegen, `fsync`, `rename`, `fsync` des Ordners, Aufräumen bei Fehler: `token.rs:219-247`. Ein Symlink oder eine fremde Datei als Ziel wird abgelehnt: `token.rs:165-177`.
- Unter `sudo` gehört die Datei schon beim Anlegen root (euid/egid 0), mit Modus ≤0600. Das spätere `chown` ändert praktisch nichts: `token.rs:222-237`.
- Migration in sicherer Reihenfolge: Token-Datei, Sicherung ohne Token (Zeilen mit `token =` entfernt), dann Konfiguration mit altem Modus und Besitzer. Ein Parse-Fehler bricht vor jedem Schreiben ab: `setcmd.rs:134-159`, `token.rs:268-300`.
- Ausgaben zeigen nur Pfad und Fingerabdruck (8 Hex-Zeichen von SHA-256): `setcmd.rs:168-177`, `status.rs:167-179`. `last-run` speichert nur ein Ergebniswort, die Anzeige wird gefiltert: `status.rs:30-40`, `:52-70`. Die 401/403-Meldung enthält keinen Token: `error.rs:32-38`.
- HTTP ohne Redirects (Bearer verlässt den Zielserver nicht), `/healthz` in `status` ohne Token: `agent/src/send.rs:14-21`, `status.rs:217-220`.
- install.sh: Prüfsumme nur für genau den Dateinamen, eindeutig, 64 Hex: `install.sh:104-118`. minisign ist Pflicht, ein Platzhalter oder fehlendes minisign führt zum Abbruch: `:120-131`. Den Token schreibt das Builtin `printf`, er steht nie in einer Argumentliste: `:261`. Ein vorhandener Token bleibt unangetastet: `:65-66`. Das Update lädt nur das Binary: `:239-243`.

**2. Abruf-Läufe**
- Routen `POST /feeds/{name}/run` und `POST /feeds/refresh` verlangen `CsrfAdmin`, `GET /feeds/runs` verlangt `Admin`: `server/src/routes/feeds.rs:802-803`, `:900-901`, `:859-860`; Routing `routes/mod.rs:98-100`.
- CSRF bei jedem Nicht-GET, Vergleich in konstanter Zeit, Konten mit Pflicht-Passwortwechsel werden abgelehnt: `server/src/extract.rs:51-61`, `:71-83`, `:98-105`; `security.rs:33-35`.
- Regeln 60 s, Backoff mit Bestätigung (428) und 5 min im Backoff, mit `Retry-After`: `server/src/cve/runs.rs:20-22`, `:698-747`; `feeds.rs:764-789`.
- 409 bei laufendem Lauf über einen eindeutigen Teilindex plus `ON CONFLICT DO NOTHING`: `migrations/0017_feed_runs.sql:27`, `runs.rs:387-410`, `feeds.rs:791-799`, `:834`.
- Live-Ereignisse der Läufe enthalten nur ID, Quelle, Status, Phase und Zähler, keine Fehlertexte: `runs.rs:448-459`. Die Zusatzspalten enthalten nur Zahlen: `migrations/0019_feed_run_metrics.sql`, `0020_feed_run_transfer.sql`. Fehler beim Bauen einer Quelle nennen kein Geheimnis: `cve/sources.rs:218`, `:293-312`. `limit` von `/feeds/runs` ist auf 1..50 begrenzt: `feeds.rs:864-867`.

**3. Filter, Sortierung, Suche, Paginierung**
- CVE-Liste: Whitelists für `distro`, `split`, `debian`/`ubuntu`, `affects`, `dir`, `sort`; unbekannte `releases`-Werte gelten als `mine`: `server/src/routes/cves.rs:228-252`, `:374-380`, `:391-417`. In `format!` gelangen nur Konstanten und gewhitelistete Werte (`chips_sql`-Quelle aus der Whitelist bzw. Literalen: `:148-150`, `:297`, `:317-329`). Die Suche ist ein gebundener Parameter: `:450-452`.
- `limit` auf 1..500 begrenzt, `offset` ≥ 0 (Zahlen, keine Strings in SQL): `cves.rs:387-388`, `:428-436`.
- LIKE-Metazeichen `\`, `%`, `_` werden mit dem Postgres-Standard-Escape `\` entschärft: `cves.rs:261-268`, `hosts.rs:279-285`, `:449-455`.
- Host-CVEs: Status-Liste, Gruppe, Richtung, Sortierung und `kind` per Whitelist, `limit` 1..1000, `offset` ≥ 0, `level_min` 0..10, alle Werte gebunden: `server/src/routes/hosts.rs:228-274`, `:313-360`, `:440-444`.
- Nullbytes: `%00` wird in Pfad und Query global abgelehnt (`routes/mod.rs:141-152`), Steuerzeichen in der CVE-Suche zusätzlich (`cves.rs:254-259`). Die übrigen `format!`-SQL-Stellen (`hostops.rs:69,81,206`, `cve/reeval.rs:46,358`) setzen nur Konstanten ein.

**4. Header, Cookies, WebSocket**
- Session-Cookie `HttpOnly; SameSite=Strict; Path=/; Secure` (Secure standardmäßig an, `config.rs:229`): `server/src/security.rs:59-62`, gesetzt in `routes/auth.rs:73-83`.
- CSRF-Token mit 24 Byte Zufall je Session (`security.rs:25-27`), im Web nur im Speicher gehalten und nur bei Schreibzugriffen gesendet: `web/src/lib/api.ts:28-38`.
- Kein CORS-Layer im Server (grep `cors` ohne Treffer in `server/src`), also keine Freigabe für fremde Origins; `x-csrf-token` erzwingt zudem einen Preflight.
- `/api/v1/live`: Admin-Session ist Pflicht (vor dem Upgrade), Origin muss zu `Host` passen oder in `PATCHWATCH_ALLOWED_ORIGINS` stehen (exakter Vergleich, `null` und Suffix-Tricks werden abgelehnt), Semaphore mit 64 Plätzen, Frames höchstens 1 KB, Ping/Idle 25/75 s, Session-Neuprüfung alle 60 s mit Close 4401: `server/src/routes/live.rs:20-63`, `:65-116`; `config.rs:328-334`.
- Web-Header nosniff, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, Permissions-Policy: `web/next.config.ts:24-27`. HSTS in Caddy: `deploy/Caddyfile:15`. Die Avatar-Antwort hat CSP `default-src 'none'`, nosniff und CORP same-origin und liefert nur die Typen PNG/WebP aus: `server/src/routes/auth.rs:198-223`, `:236-243`.

**5. Web**
- Einziges `dangerouslySetInnerHTML` ist die Konstante `THEME_SCRIPT`. Sie vergleicht localStorage-Werte nur mit festen Strings: `web/src/app/layout.tsx:22`, `:28`. Kein `innerHTML`, `insertAdjacentHTML`, `eval` oder `new Function` in `web/src` (grep).
- Toasts zeigen Titel, Text und Aktion als React-Text: `web/src/components/Toaster.tsx:88-108`. Server-Benachrichtigungen per WebSocket ebenso: `web/src/lib/live.tsx:66-72`.
- Quellennamen (`check_label`, keine Steuerzeichen: `feeds.rs:466-480`), Hostnamen, CVE-Beschreibungen und Lauf-Fehler werden nur als Text dargestellt (z. B. `RunStepper.tsx:98`, `FeedSources.tsx:133,157`).
- Links: `Linkified` macht nur `http(s)://` klickbar (`components/Linkified.tsx:3,7`). Die Links im CVE-Detail kommen aus festen Vorlagen mit geprüfter CVE-ID (`server/src/routes/cves.rs:180-187`, Web `cves/[id]/page.tsx:219`). Zeilen-Links führen nur auf interne Pfade (`app/(app)/page.tsx:295,338`, `lib/rowLink.ts:36-42`). `base_url` wird nicht als Link dargestellt (`FeedSources.tsx:349`). Externe Links haben `rel="noopener noreferrer"`.
- Zwischenablage: Clipboard-API mit Rückfall über ein verstecktes Textfeld, das danach entfernt wird; kein Logging, nichts geht an den Server: `web/src/lib/clipboard.ts:14-58`. Angezeigte Befehle enthalten keinen Token: `web/src/lib/agentCommands.ts:1-6`.
- Der API-Cache liegt nur im Speicher und wird bei Logout und 401 geleert, mit Schutz vor späten Antworten: `web/src/lib/apiCache.ts:1-2`, `:36-54`; `components/AuthProvider.tsx:65-70`.

---

## Nicht prüfbar ohne Ausführung

- Ob `stty -echo` bzw. `stty echo` auf allen Zielsystemen greift und das Echo nach Strg+C oder SIGTERM wieder an ist (Agent und install.sh).
- Tatsächlicher Besitzer und Gruppe beim Anlegen unter verschiedenen `sudo`/`su`-Konfigurationen (egid, setgid-Ordner).
- Ob die TOCTOU-Fenster (N3, N4, N12) in der Praxis treffbar sind.
- Wie stark ein Suchtext von ~64 KB Postgres tatsächlich belastet (N8); ob Caddy/Next.js lange URIs vorher abweisen.
- Ob Caddy `Host`, `Origin` und das WebSocket-Upgrade unverändert durchreicht und die Origin-Prüfung hinter dem Proxy wie erwartet greift.
- Welche Header Next.js tatsächlich auf statische Assets und Fehlerseiten setzt; ob eine CSP mit den Inline-Skripten von Next.js verträglich ist.
- Browser-Verhalten (schemeful same-site) für N10.
- Ob reqwest-Fehler zur Laufzeit wirklich nie URLs mit Query-Parametern oder Header enthalten (Code nutzt `without_url()`; NVD-Schlüssel nur im Header).
- Ob echte Parser-Fehlertexte (N13) Inhalte aus den Feeds enthalten.
- Ob `printf` in der auf dem Zielsystem genutzten `/bin/sh` ein Builtin ist (in dash/bash ja; sonst stünde der Token in der Argumentliste).
- Ob der Release-Prozess den Platzhalter `PW_PUBKEY` vor der Veröffentlichung ersetzt (laut README und Test schlägt die Installation bis dahin absichtlich fehl).

---

## Auffälliges (keine Funde im engeren Sinn)

- `PW_PUBKEY` steht noch auf dem Platzhalter (`install.sh:97`). Installation und Update scheitern absichtlich, bis der Schlüssel eingetragen ist (README:43). Das ist fail-closed und korrekt, solange es so bleibt.
- Die UI-Hilfe auf der Agents-Seite nennt nur die SHA256-Prüfung, nicht minisign (`agents/page.tsx:57-58`).
- `--migrate` übernimmt den vorhandenen Klartext-Token nicht, sondern verlangt einen neuen per Eingabe. Die neue agent.toml wird vor dem Ersetzen nicht neu geparst (`setcmd.rs:147-153`). Das betrifft die Robustheit, nicht die Sicherheit.
- `PATCHWATCH_TOKEN` bleibt in install.sh exportiert und wird an alle Kindprozesse vererbt (curl, minisign, das Agent-Binary). Nur root kann das lesen; ein `unset` nach dem Einlesen wäre sauberer.
- `hosts.rs:314-317`: `fix_version` mit mehr als 128 Zeichen wird stillschweigend ignoriert (ungefilterte Liste statt 400).
- `GET /feeds/runs?active=true` hat eine schreibende Nebenwirkung (`sweep_stale`, `feeds.rs:870`). Das ist harmlos, weil es nur verwaiste Läufe beendet.
- Außerhalb des Diffs (seit dem Audit unverändert): Die Watchlist-Notiz (`cves.rs:580-585`) lehnt keine NUL-/Steuerzeichen ab. `\u0000` im JSON führt vermutlich zu einem 500 statt 400.
- Der Token wird zum Kopieren in die System-Zwischenablage gelegt (beabsichtigt) und nicht wieder entfernt. Zwischenablage-Verläufe können ihn behalten.
