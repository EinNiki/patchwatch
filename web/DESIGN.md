# patchwatch – Design

Verbindlich für das ganze UI. Abweichungen nur hier ändern, dann im Code nachziehen.

## Charakter

Ruhige, dichte Ops-Konsole für Admins. **Informationsdichte vor Dekoration.** Eine Tabelle ist das
Hauptwerkzeug; alles andere ordnet sich ihr unter. Keine Marketing-Sprache, keine Begrüßungsfloskeln,
keine Animationen außer funktionalen (Fokus, Aufklappen), und die respektieren `prefers-reduced-motion`.

Verboten (aus dem Briefing): lila-blaue Verläufe, Glassmorphism, Hero-Banner, Karten-Raster mit
Emoji-Icons, überall gleiche Rundungen/Schatten, Platzhaltertexte im Marketing-Stil, „Willkommen zurück“.

## Schrift

| Zweck | Schrift | Einsatz |
|---|---|---|
| Text | **Atkinson Hyperlegible Next** | UI, Fließtext, Tabellenköpfe. Auf Lesbarkeit und eindeutige Zeichen (I/l/1, O/0) ausgelegt, keine Inter/Roboto/Arial-Standardwahl. |
| Daten | **IBM Plex Mono** | Versionsnummern, Kernel, Paketnamen, CVE-IDs, Tokens. Immer `font-variant-numeric: tabular-nums`. |

Beide lokal über `@fontsource` eingebunden (keine Anfragen an Google, funktioniert im VPN ohne Internet).
Skala (px): 12 (Meta), 13 (Tabellen), 14 (Basis), 16 (Abschnitt), 20 (Seitentitel). Zeilenhöhe 1,45. Keine fetten Überschriften über 600.

## Farben

Wenige Töne: warmes Neutral, **ein Akzent** (Tintenblau, nur für Links, Fokus, aktive Navigation, Auswahl),
vier semantische Statusfarben. Der Akzent ist bewusst nicht grün/gelb/rot, damit er nie als Status gelesen wird.
Werte als CSS-Variablen in `src/app/globals.css`; Kontrast mit WCAG-Formel gerechnet (Zahlen = Verhältnis).

| Token | Hell | Dunkel | Zweck |
|---|---|---|---|
| `bg` | `#F6F4EF` | `#141412` | Seite |
| `surface` | `#FDFCFA` | `#1B1A17` | Tabellen, Panels |
| `sunk` | `#EDEAE2` | `#232220` | Tabellenkopf, Eingabefelder-Hintergrund, Code |
| `line` | `#D6D1C5` | `#3A3832` | Haarlinien (dekorativ) |
| `control` | `#8A8578` | `#7A766B` | Rand von Eingaben/Buttons (≥ 3:1) |
| `text` | `#1D1C18` (16,6) | `#ECE9E1` (14,3) | Haupttext |
| `text-2` | `#524F47` (8,0) | `#B7B3A7` (8,3) | Sekundär |
| `text-3` | `#686459` (5,8) | `#9A968B` (5,9) | Meta, Platzhalter (≥ 4,5) |
| `accent` | `#1B5586` (7,6) | `#86B9EA` (8,4) | Akzent |

### Status (semantisch)

Status wird **nie nur über Farbe** vermittelt: jede Statusanzeige hat **Icon (eigene Form) + Text + Farbe**.

| Klasse | Hell (Text / Fläche) | Dunkel (Text / Fläche) | Icon-Form | Bedeutung |
|---|---|---|---|---|
| `ok` | `#1C6637` / `#E2EFE6` (5,9) | `#7FCF9B` / `#1B2E22` (7,7) | Kreis + Haken | in Ordnung |
| `warn` | `#835000` / `#F9ECCF` (5,8) | `#EBB75A` / `#33280F` (7,9) | Dreieck + `!` | Handlung bald nötig |
| `crit` | `#A0211A` / `#FAE2DF` (6,2) | `#F5897F` / `#3C1C19` (6,4) | Raute + `×` | Handlung jetzt nötig |
| `unknown` | `#4A5361` / `#E6E9EE` (6,4) | `#B3BBC9` / `#272B32` (7,4) | gestrichelter Kreis + `?` | Datenlage fehlt/unklar, **nie „grün“** |

Zuordnung Host-Status: Aktuell → ok · Updates offen, Neustart nötig → warn · Sicherheitsupdates offen,
Verwundbar (CVE) → crit · Meldet sich nicht, Kein Report → unknown.
CVE-Status: behoben, nicht betroffen → ok · Fix angekündigt, gefixt installiert/Neustart nötig → warn ·
verwundbar → crit · unbekannt → unknown.
Zusätzliche Marker mit eigenem Icon: Neustart (Kreispfeil), veraltet/stale (Uhr).

## Abstände, Form, Tiefe

- Raster 4 px (`1 = 4px`). Zellen: 8 px vertikal, 12 px horizontal. Seitenrand 16 px (Mobil) / 24 px.
- **Rundungen nach Rolle, nicht einheitlich:** Tabellen 0 (nur Haarlinien), Badges 2 px, Eingaben/Buttons 3 px,
  Dialog 6 px. Keine Pillen.
- **Schatten nur dort, wo etwas schwebt** (Dialog). Sonst Trennung durch Haarlinien und Flächentöne.
- Max. Inhaltsbreite 1440 px. Keine Karten; Bereiche sind Abschnitte mit Überschrift und Haarlinie.

## Komponenten

- **Tabelle** (Hauptelement): Kopf in `sunk`, Haarlinien zwischen Zeilen, Zeilen-Hover `sunk` 50 %, sortierbare Köpfe
  sind `<button>` in `<th aria-sort>`. Zahlen/Versionen rechtsbündig bzw. mono. Mobil (< 768 px): Zeilen werden
  gestapelt, jede Zelle trägt ihr Label (`data-label`).
- **Statusanzeige** (`StatusBadge`): 2-px-Rundung, Fläche = Statusfläche, Text = Statusfarbe, Icon links, Text immer sichtbar.
- **Leerzustände:** sagen, was fehlt und was als Nächstes zu tun ist (konkret, ohne Floskeln).
- **Kopfzeile:** Navigation (Hosts · CVEs · Matrix [„bald“, nicht anklickbar] · Einstellungen), rechts Feed-Zustand,
  Theme (System/Hell/Dunkel), Abmelden. Feed-Zustand ist immer sichtbar; veraltete Feeds sind `warn`.
- **Details-Block:** Begründungen einer CVE-Bewertung per `<details>`: Text + Quellen-Tabelle.
- **Kleine Details:** relative Zeit mit absolutem `title` und `<time datetime>`; Kernel-Version zeigt laufend ≠ neueste
  als `6.8.0-31 → 6.8.0-35`; Token nur einmal sichtbar mit „Kopieren“; Zählerzellen mit `0` gedämpft statt farbig.

## Barrierefreiheit

- Text ≥ 4,5:1 (gemessen oben), Bedienelement-Ränder ≥ 3:1, Fokusring 2 px `accent` mit 2 px Abstand auf allen Fokussierbaren.
- Vollständig per Tastatur bedienbar; „Zum Inhalt springen“-Link; Tabellen mit `<caption>` (visuell versteckt);
  `aria-sort`, `aria-live` für Rückmeldungen, `aria-current="page"` in der Navigation, `<dialog>` für Bestätigungen.
- Statusinformation nie nur über Farbe; Mindestgröße Zielfläche 32 px (Touch: 44 px).
- Hell/Dunkel folgt dem System, manuell umschaltbar (wird gemerkt); `prefers-reduced-motion` wird beachtet.

## Texte

Deutsch, präzise, im Imperativ oder Aussagesatz. Beispiele: „Noch kein Report“, „Neustart nötig“,
„Fix angekündigt (voraussichtlich in 7.0.0-43.43)“, „Quelle veraltet seit 29.10., 21:34“.
Keine Ausrufezeichen, keine Emoji, keine Anrede.
