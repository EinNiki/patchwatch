# patchwatch – Design v2

Verbindlich für das ganze UI (Stand: Branch `feat/ui-v2`). v1 liegt unverändert unter `docs/design/v1/`
(Tag `design-v1`). Abweichungen nur hier ändern, dann im Code nachziehen. Referenzen: lokale Skills `hig`
(Prüfliste, siehe `docs/design/v2/skills-review.md`), `design`, `ui-ux-pro-max`, `ui-styling`; bei Konflikten gilt dieses Dokument.

## Charakter

Moderner, aber weiterhin **dichter Ops-Betrieb**. Klar gegliederte, ruhige Flächen, deutliche Hierarchie,
eine feste **Seitenleiste** statt Top-Navigation. Die Tabelle bleibt das Hauptwerkzeug; Chips tragen den Status.
Keine Marketing-Sprache, keine Begrüßungsfloskeln, Bewegung nur funktional (Fokus, Aufklappen, Seitenleiste auf Mobil)
und mit `prefers-reduced-motion` abgeschaltet.

Verboten: lila/blaue Verläufe, Glassmorphism/Blur, Hero-Banner, Karten-Raster mit Emoji-Icons, Emoji überhaupt,
überall gleiche Rundungen/Schatten, Platzhaltertexte im Marketing-Stil, „Willkommen zurück“, Apple-Muster (Tab-Bars,
SF Symbols, Systemfarben, Kapsel-Buttons).

## Layout

```
┌──────────────┬──────────────────────────────────────────────┐
│ Seitenleiste │ Seitenkopf: Titel · Zählung · Aktionen        │
│  232 px      ├──────────────────────────────────────────────┤
│  Navigation  │ Inhalt (max. 1440 px, Ränder 24 px)           │
│  Status unten│                                              │
└──────────────┴──────────────────────────────────────────────┘
```

- **Seitenleiste** (`nav`, `aria-label="Hauptnavigation"`): Marke `patchwatch` (mono), dann **Hosts · CVEs · Agents ·
  Benachrichtigungen · Einstellungen**. „Benachrichtigungen“ hat eine zweite Ebene (ntfy, Matrix, Gotify, Discord,
  Live im Browser), mehr als zwei Ebenen gibt es nicht. Aktive Seite: `aria-current="page"`, linke 3-px-Leiste in
  `accent` + `accent-soft`-Fläche + fetter Text. Unten (nicht kritisch): CVE-Feed-Zustand, Live-Status, Konto
  (Name, Abmelden). Kein Matrix-Eintrag; die Matrix kommt später als Umschalter „Liste | Matrix“ auf der CVE-Seite.
- **Mobil (< 900 px):** Seitenleiste ist eingeklappt. Kopfzeile (48 px) mit Menü-Button (Beschriftung „Menü“, 44 px),
  Seitenname. Auf: Off-Canvas von links, Hintergrund `bg` mit 40 %-Abdunklung (kein Blur), Fokus wandert hinein und
  bleibt gefangen, `Esc`/Klick daneben/Navigieren schließt, Fokus kehrt zum Menü-Button zurück.
- **Seitenkopf:** `h1` 20 px/600, daneben Zählung in `text-3`, rechts die Hauptaktion der Seite (genau eine primäre).
- **Flächenebenen:** (1) `bg` Seitenhintergrund, (2) `surface` Panels/Tabellen mit 1-px-`line`-Rand, (3) `sunk`
  eingelassen (Tabellenkopf, Eingabefelder, Code). Gruppierung zuerst über Abstand, Linien nur zur Trennung von Zeilen.
- Abschnitte innerhalb einer Seite: `h2` 16 px/600 mit 24 px Abstand davor; Zusammengehöriges mit 8 px.

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

- Raster 4 px (`1 = 4px`). Zellen: 8 px vertikal, 12 px horizontal. Panel-Innenabstand 16 px. Seitenrand 16 px (Mobil) / 24 px.
- **Rundungen nach Rolle:** Tabellen/Panels 0–2 px, Chips 2 px, Eingaben/Buttons 3 px, Dialog/Toast 6 px. Keine Pillen.
- **Schatten nur für Schwebendes** (Dialog, Toast, Off-Canvas). Sonst Flächentöne und Haarlinien.
- Icons: eigene Inline-SVGs (16 px, 1,5-px-Strich, `currentColor`), `aria-hidden`; Status-Icons unterscheiden sich in der
  **Form**, nicht nur in der Farbe. Keine Emoji.

## Chips (Status und Distro)

Chip = 2-px-Rundung, 12 px/500, Höhe 22 px, Padding 0 6 px, Icon links (14 px), Text immer sichtbar.

| Chip | Aufbau | Beispiel |
|---|---|---|
| **Status** (`StatusBadge`) | Fläche = Statusfläche, Text/Icon = Statusfarbe | `[◆× Verwundbar]` |
| **Distro** (`DistroChip`) | Status-Icon + `Distro Release` (Text) + Status-Wort + Fix-Version in Mono | `[✓ Debian trixie · gefixt 6.12.113-1]` · `[⏳ Ubuntu noble · Fix in Arbeit]` · `[◆× Ubuntu jammy · verwundbar]` · `[– nicht betroffen]` · `[? unbekannt]` |
| **Marker** | gedämpft, Rahmen statt Fläche | Neustart nötig, veraltet, Watchlist, Proxmox |

Die Zeichen in der Tabelle sind nur Platzhalter für die SVG-Formen (Haken, Uhr/Sanduhr-Form für „Fix in Arbeit“,
Raute-×, Strich, Fragezeichen). Zuordnung zu Klassen: gefixt, nicht betroffen → `ok` (nicht betroffen: gedämpft,
Text `text-3`) · Fix in Arbeit → `warn` · verwundbar → `crit` · unbekannt → `unknown`.
Standardmäßig nur Releases anzeigen, die auf mindestens einem Host laufen; weitere per „Alle Releases“ (`<details>`).

## Buttons

- **Varianten:** *Primär* (Fläche `accent`, Text `bg`-Ton, genau **eine** je Bereich), *Sekundär* (Rand `control`, Fläche `surface`),
  *Tertiär* (nur Text in `accent`, für Tabellenzeilen), *Destruktiv* (Rand/Text `crit`; wird erst im Bestätigungsdialog gefüllt).
  Stil unterscheidet die bevorzugte Aktion, nicht die Größe.
- **Beschriftung:** Verb + Objekt („Token erneuern“, „Agent hinzufügen“), „…“ nur wenn ein weiterer Schritt folgt.
  Nie „OK“; Dialogbuttons benennen die Aktion („Agent löschen“), daneben „Abbrechen“ (Standardfokus bei destruktiven Dialogen).
- **Größe:** Höhe 32 px (Desktop), 44 px bei Touch (`pointer: coarse`); Abstand zwischen Buttons ≥ 8 px.
- **Zustände** (alle Pflicht): hover (Fläche +4 % Kontrast), active (leicht abgedunkelt), `:focus-visible` (Ring 2 px `accent`,
  Abstand 2 px), disabled (`aria-disabled`, 60 % Deckkraft, Grund per Text/`title`), busy (Spinner-Icon + Text bleibt,
  `aria-busy`, Klick gesperrt).
- Aktionen, die > 1 s dauern, zeigen Fortschritt (Zustand am Button oder Zeile, z. B. „wartet auf Agent …“).

## Formulare

- Label immer sichtbar über dem Feld (kein Platzhalter als Label), Hilfetext 12 px `text-3` darunter, Fehler darunter mit Icon + Text
  in `crit`, `aria-invalid` + `aria-describedby`. Validierung beim Verlassen des Felds und beim Absenden.
- Feldbreite passend zur Eingabe (Name 24 ch, URL 48 ch, Zeit 8 ch). Eingabefläche `sunk`, Rand `control`.
- **Geheimnisse (write-only):** nach dem Speichern zeigt das Feld „Gespeichert · ersetzen“ mit Schaltfläche „Ersetzen“ und
  „Entfernen“; der Wert wird nie angezeigt oder vom Server zurückgegeben.
- Ein/Aus: Checkbox mit Label; „Kanal aktiv“ als Schalter-Checkbox mit Text „An/Aus“; ≥ 3 exklusive Optionen = Radiogruppe.
  Zustand nie nur über die Farbe (Haken/Position + Text).
- Segmentierte Steuerung (später „Liste | Matrix“): 2–3 gleich breite Segmente, Substantive, `role="radiogroup"`.

## Komponenten

- **Tabelle:** Kopf `sunk`, Haarlinien, Zeilen-Hover `sunk` 50 %, sortierbare Köpfe als `<button>` in `<th aria-sort>`, Zahlen/Versionen
  rechtsbündig bzw. mono, Aktionsspalte rechts. Mobil (< 768 px): Zeilen gestapelt, jede Zelle mit `data-label`.
- **Dialog** (`<dialog>`, modal): Titel, kurzer Text, Objektname fett, Buttons rechts; Esc schließt; nicht für reine Information.
- **Toast** (Live-Benachrichtigung): rechts unten, `role="status"` (kritisch: `role="alert"`), Icon + Text, sichtbar 8 s, per Tastatur
  schließbar, nie die einzige Quelle (Eintrag steht auch in der Liste). Nicht gestapelt über 3.
- **Leerzustände:** sagen, was fehlt und was als Nächstes zu tun ist, mit einer Aktion („Agent hinzufügen“). **Fehlerzustände:**
  Ursache in einem Satz, „Erneut versuchen“, Stand der Daten (z. B. „Daten von vor 5 Min.“) bleibt sichtbar.
- **Details-Block:** Begründungen einer CVE-Bewertung per `<details>`. **Kleine Details:** relative Zeit mit absolutem `title` und
  `<time datetime>`; Kernel `6.8.0-31 → 6.8.0-35` bei laufend ≠ neueste; Token nur einmal sichtbar mit „Kopieren“;
  Nullwerte gedämpft statt farbig.
- **Live-Anzeige:** Punkt-Icon + Text „Live“ (verbunden) / „Getrennt, verbinde neu …“; Änderungen aktualisieren die Zeile ohne Sprung
  (`aria-live="polite"` nur für Zusammenfassungen, nicht für jede Zeile).

## Barrierefreiheit

- Text ≥ 4,5:1 (Tabellen oben), UI-Ränder/Icons ≥ 3:1, Fokusring auf allem Fokussierbaren.
- Vollständig per Tastatur bedienbar: „Zum Inhalt springen“, Seitenleiste mit Pfeil-/Tab-Navigation, Dialoge mit Fokusfalle,
  `aria-current`, `aria-sort`, `aria-live` für Rückmeldungen, Tabellen mit `<caption>` (visuell versteckt).
- Statusinformation nie nur über Farbe. Zielgröße 32 px (Touch 44 px) plus Abstand.
- Hell/Dunkel folgt dem System, umschaltbar (Einstellungen, wird gemerkt); `prefers-reduced-motion` beachtet.

## Texte

Deutsch, präzise, Aussagesatz oder Imperativ. Beispiele: „Noch kein Report“, „Neustart nötig“, „wartet auf Agent …“,
„Token wird nicht erneut angezeigt“, „Fix angekündigt (voraussichtlich in 7.0.0-43.43)“. Keine Ausrufezeichen, kein Emoji, keine Anrede.
