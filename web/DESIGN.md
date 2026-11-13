# patchwatch – Design v2.1

Verbindlich für das ganze UI (Stand: Design-Pass auf `feat/ui-v2`). v1 liegt unverändert unter `docs/design/v1/`
(Tag `design-v1`). Abweichungen nur hier ändern, dann im Code nachziehen. Referenzen: lokale Skills `hig`
(Prüfliste, siehe `docs/design/v2/skills-review.md`) und `frontend-design` (nur als Muster-Checkliste); bei Konflikten gilt dieses Dokument.
Alle Werte stehen als Tokens in `src/app/tokens.css`.

## Charakter

Ein **Werkzeug**: ruhig, flach, dicht. Kühle Neutraltöne, **eine** Akzentfarbe, Statusfarben nur in Chips und Icons.
Die Tabelle ist das Hauptwerkzeug und nutzt die volle Breite. Keine Marketing-Sprache, keine Begrüßungsfloskeln.
Dunkel ist der Hauptmodus (Standard folgt dem System), Hell ist gleichwertig und wird gleich geprüft.

Verboten: Verläufe, Glassmorphism/Blur, Hero-Bereiche, Karten-Raster mit Emoji-Icons, Emoji überhaupt, überall gleiche
Rundungen/Schatten, Schatten-Teppich, warmer Creme-Hintergrund, Mittelpunkte als Trenner in Chips, ALL-CAPS-Labels,
Apple-Muster (Tab-Bars, SF Symbols, Systemfarben, Kapsel-Buttons), „mutige“ Effekte.

## Layout und Platz

```
┌────────┬──────────────────────────────────────────────────────┐
│ 220 px │ Seitenkopf: Titel · Zählung · Aktion  (eine Zeile)    │
│ Navi   ├──────────────────────────────────────────────────────┤
│ fest   │ Inhalt, volle Breite, Ränder 16 px (mobil) / 24 px    │
└────────┴──────────────────────────────────────────────────────┘
```

- **Volle Breite:** Tabellen und Listen haben keine Maximalbreite. Nur Formulare und Fließtext sind auf ca. 45 rem (≈ 720 px) begrenzt.
- **≥ 1600 px (`wide`):** zusätzliche Spalten (CVE „Prio“, Hosts „Agent“, „Kernel neueste“), Distro-Chips nebeneinander,
  Detailseiten zweispaltig (Hauptinhalt links, Meta rechts).
- **Einstellungen:** je Abschnitt zweispaltig (links Titel + Kurzbeschreibung, rechts Formular). **Benachrichtigungen:** ab 1024 px Kanalliste
  links, Formular rechts; mobil einspaltig.
- **Hosts:** kompakte Kennzahlenleiste (verwundbar, Sicherheitsupdates, Neustart nötig, meldet sich nicht, zuletzt gemeldet; es gibt bewusst keine Kachel „unbekannt“), zugleich Filter; darunter die Tabelle.
- **Seitenleiste** (`nav`, `aria-label="Hauptnavigation"`): Marke `patchwatch` (mono), **Hosts · CVEs · Agents ·
  Benachrichtigungen · Einstellungen**. „Benachrichtigungen“ hat eine zweite Ebene (ntfy, Matrix, Gotify, Discord, Live im Browser),
  mehr Ebenen gibt es nicht; die Gruppe hat einen eigenen Auf/Zu-Knopf (`aria-expanded`), ihr Zustand steht in `localStorage`
  (`pw-nav:notifications`) und wird beim Seitenwechsel nicht zurückgesetzt; auf Unterseiten ist sie immer offen.
  Aktive Seite: `aria-current="page"`, fetter Text und eine **gleitende Fläche** (ein Element hinter den Zeilen mit 2-px-Leiste in
  `accent`; nur `transform`, 200 ms; Größenänderungen der Leiste folgen ohne Übergang, beim Laden springt sie ohne Animation).
  Zähler: Hosts mit kritischem Stand (Zahl rechts, Text für Screenreader), Kanäle mit Fehler (Punkt am Symbol). Die Kanäle der Gruppe
  hängen an einer Führungslinie unter dem Symbol. Unten: Feed-Zustand, Live-Status, Konto, Abmelden (alles als Zeilen mit festem Symbolplatz).
- **Responsive** (min-width-Breakpoints: `md` 768, `lg` 1024, `xl` 1440, `wide` 1600, `2xl` 1920; Prüfbreiten 390, 480, 768, 1024, 1440, 1920):
  - ≥ 1024: Seitenleiste fest, 220 px; per Knopf neben der Marke einklappbar (dann wird die Marke zur Schaltfläche „Einblenden“).
    Breite und Inhaltsrand animieren in 240 ms, Beschriftungen blenden in 120 ms aus. Zustand in `localStorage` (`pw-nav:collapsed`);
    ein Skript im `<head>` setzt `html[data-sb="collapsed"]` vor dem ersten Bild (kein Aufblitzen, keine Animation beim Laden).
  - 768–1023: immer Icon-Rail, 56 px (nicht umschaltbar), Tooltips bei Hover **und** Fokus, Name bleibt im Link lesbar.
    Eingeklappt ab 1024 sieht die Leiste genauso aus. Technisch: eigene Tailwind-Variante `rail` (globals.css).
  - < 768: Off-Canvas mit Kopfzeile (48 px); Fokusfalle, `Esc`, Klick auf den Hintergrund und Navigieren schließen; Fokus kehrt zum Menü-Button zurück.
  - Tabellen < 768: gestapelte Einträge (Name oben, Status-Chips darunter, Nebenwerte klein). Zu breite Tabellen scrollen in
    ihrem Container, nie die Seite (`scrollWidth ≤ innerWidth` ist ein Test).
  - Große Schrift: Media-Queries rechnen rem immer mit 16 px, Container-Queries mit der tatsächlichen Schriftgröße. Tabellen
    stapeln deshalb zusätzlich, wenn ihr Behälter (`@container/tbl`) schmaler als 40 rem ist (Varianten `stacked`,
    `stacked-lg`, `tabular` in `globals.css`); bei 16 px Schrift ist der Behälter ab 768 px immer breiter, dort ändert sich nichts.
    Bei 200 % Schrift und 1280 px verhalten sich Tabellen und Host-Seite so wie in einem schmalen Fenster.
  - Touch (< 768): Trefferflächen ≥ 44 px, Filterleiste hinter „Filter (n)“, Dialoge als Bottom-Sheet.
- **Flächen:** `bg` Seite, `surface` Tabellen/Inhalt, `sunk` eingelassen (Tabellenkopf, Eingaben, Code). Kein Rahmen-Kasten um Tabellen
  (nur Linien oben/unten und zwischen Zeilen); Gruppierung zuerst über Abstand.
- **Seitenkopf:** `h1` 18 px/600, Zählung in `text-3`, rechts die eine primäre Aktion. Abschnitte: `h2` 16 px/600, 24 px Abstand davor.

## Schrift

| Zweck | Schrift | Einsatz |
|---|---|---|
| Text | **Atkinson Hyperlegible Next** | UI, Fließtext, Tabellenköpfe. Auf Lesbarkeit und eindeutige Zeichen (I/l/1, O/0) ausgelegt. |
| Daten | **IBM Plex Mono** | Zahlen, Versionen, Kernel, Paketnamen, CVE-IDs, Tokens. Immer `tabular-nums`. |

Lokal über `@fontsource` (keine Anfragen an Google). Stufen in **rem** (`html` bleibt bei 100 %, damit Schriftvergrößerung wirkt):
`xs` 12 (Meta, Chips) · `sm` 13 (Tabellen, Formulare) · `base` 14 (Fließtext) · `lg` 16 (h2) · `xl` 18 (h1). Hierarchie über Gewicht (400/600)
und Graustufen, nie über Größe allein. Zeilenhöhe 1,45.

## Farben

Kühles Neutral, **ein Akzent** (gedecktes Blau, nur für Links, Fokus, aktive Navigation, Auswahl), vier Statusfarben, die ausschließlich in
Chips und Icons vorkommen. Kontrast nach WCAG gerechnet (Zahl = Verhältnis; Skript im Pass-Verlauf, Werte unten).

| Token | Hell | Dunkel | Zweck |
|---|---|---|---|
| `bg` | `#F6F7F8` | `#15171A` | Seite |
| `surface` | `#FFFFFF` | `#1A1D21` | Tabellen, Inhalt |
| `sunk` | `#EEF0F2` | `#202328` | Tabellenkopf, Eingaben, Code |
| `line` | `#E1E4E8` | `#2B2F35` | leise Linien (dekorativ) |
| `control` | `#7C8590` (3,7) | `#6B7480` (3,6) | Rand von Eingaben/Buttons (≥ 3:1 auf `surface`) |
| `text` | `#1B1E22` (16,7) | `#E4E6E9` (13,5) | Haupttext |
| `text-2` | `#4A5059` (8,1) | `#A8AEB6` (7,6) | Sekundär |
| `text-3` | `#5F6670` (5,8) | `#8A919A` (5,3) | Meta, Platzhalter |
| `accent` | `#2A5BB8` (6,4) | `#7EA6E8` (6,9) | Akzent (Werte auf `surface`) |

### Status (semantisch)

Status wird **nie nur über Farbe** vermittelt: jede Statusanzeige hat **Icon (eigene Form) + Text + Farbe**.

| Klasse | Hell (Text / Fläche) | Dunkel (Text / Fläche) | Bedeutung |
|---|---|---|---|
| `ok` | `#1B6B3C` / `#E3F1E8` (5,6) | `#7FCF9B` / `#18291F` (8,2) | in Ordnung |
| `warn` | `#7D4E00` / `#F8ECD2` (6,1) | `#E6B458` / `#2E2410` (8,0) | Handlung bald nötig |
| `crit` | `#A3261F` / `#FBE4E1` (6,1) | `#F28B82` / `#38191A` (6,6) | Handlung jetzt nötig |
| `unknown` | `#4B5565` / `#E8EBEF` (6,3) | `#AEB7C5` / `#252A31` (7,1) | Datenlage fehlt/unklar, **nie „grün“** |

Icon-Formen: ok Kreis + Haken · warn Dreieck + `!` · crit Raute + `×` · unknown gestrichelter Kreis + `?`.
Zuordnung Host-Status: Aktuell → ok · Updates offen, Neustart nötig → warn · Sicherheitsupdates offen, Verwundbar (CVE) → crit ·
Meldet sich nicht, Kein Report → unknown. CVE-Status: behoben, nicht betroffen → ok · Fix angekündigt, gefixt installiert/Neustart nötig → warn ·
verwundbar → crit · unbekannt → unknown. Zusätzliche Marker mit eigenem Icon: Neustart (Kreispfeil), veraltet/stale (Uhr).

## Abstände, Form, Tiefe

- Raster 4 px. **Tabellen:** Zeile 36–40 px (`td` 9 px / 12 px, 13 px Text), Kopf 32 px und **sticky**, Zahlen/Versionen mono. Seitenrand 16 px (mobil) / 24 px.
- **Rundungen nach Rolle:** Tabellen/Flächen 0, Chips 2 px, Eingaben/Buttons 3 px, Dialog/Toast 6 px. Keine Pillen.
- **Schatten nur für Schwebendes** (Dialog, Toast, Off-Canvas), sonst Flächentöne und 1-px-Linien.
- **Icons:** ein Satz, 16-px-Raster, 1,5-px-Strich, `currentColor`, `aria-hidden` (Status- und Navigations-Icons gleich). Keine Emoji.

## Chips (Status und Distro)

Chip = 2-px-Rundung, 12 px/500, Höhe 22 px, Padding 0 6 px, Icon 16 px links, Text immer sichtbar. **Kein Mittelpunkt** als Trenner.

| Chip | Aufbau | Beispiel |
|---|---|---|
| **Status** (`StatusBadge`) | Fläche = Statusfläche, Text/Icon = Statusfarbe | `[◆× Verwundbar]` |
| **Distro** (`DistroChip`) | Icon, `Distro Release` in `text-2`, Statuswort in Statusfarbe, Fix-Version in Mono | `[✓ Debian trixie gefixt 6.12.113-1]` |
| **Marker** | gedämpft, Rahmen statt Fläche | Neustart nötig, veraltet, Watchlist, Proxmox |

Standardmäßig nur Releases anzeigen, die auf mindestens einem Host laufen; weitere per „Alle Releases“ (`<details>`).

## Bewegung

Funktional, 120–200 ms (`--dur-1` 120, `--dur-2` 180), `ease-out`, nur `transform` und `opacity` (Ausnahme: Untermenü der Seitenleiste
per `grid-template-rows`, begrenzt per `contain`; Breite der Seitenleiste 240 ms, gleitende Fläche 200 ms). Keine Bibliothek, CSS
und ein kleiner Hook genügen (Messung: First-Load-JS +0,4 KB gegenüber +30–40 KB für framer-motion).

- Seitenwechsel: leiser Fade (View Transitions API, sonst CSS-Fade; keine experimentellen Flags). Dialog, Off-Canvas, Bottom-Sheet, Toast blenden ein und aus.
- Live-Update: geänderte Zeilen blitzen kurz auf (`data-flash`), Status-Chips blenden weich über.
- Ladezustand: Skeleton statt Spinner. Buttons: hover, active, busy.
- `prefers-reduced-motion`: Animationen aus oder nur noch ein kurzer Fade.

## Buttons

- **Varianten:** *Primär* (Fläche `accent`, genau **eine** je Bereich), *Sekundär* (Rand `control`, Fläche `surface`),
  *Tertiär* (nur Text in `accent`, für Tabellenzeilen), *Destruktiv* (Rand/Text `crit`; gefüllt erst im Bestätigungsdialog).
- **Beschriftung:** Verb + Objekt („Token erneuern“, „Agent hinzufügen“), „…“ nur wenn ein weiterer Schritt folgt.
  Nie „OK“; Dialogbuttons benennen die Aktion, daneben „Abbrechen“ (Standardfokus bei destruktiven Dialogen).
- **Größe:** Höhe 32 px (Desktop), 44 px bei Touch (`pointer: coarse` und < 768 px); Abstand ≥ 8 px.
- **Zustände** (Pflicht): hover, active, `:focus-visible` (Ring 2 px `accent`), disabled (`aria-disabled`, 60 %, Grund per Text/`title`), busy (`aria-busy`).
- Aktionen > 1 s zeigen Fortschritt („wartet auf Agent …“).

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

- **Tabelle:** Kopf `sunk` und sticky, leise Linien, Zeilen-Hover `sunk` 50 %, sortierbare Köpfe als `<button>` in `<th aria-sort>`, Zahlen/Versionen
  rechtsbündig bzw. mono, Aktionsspalte rechts. Mobil (< 768 px): gestapelte Einträge mit den Zellklassen `cell-primary`, `cell-status`, `cell-meta`.
- **Dialog** (`<dialog>`, modal): Titel, kurzer Text, Objektname fett, Buttons rechts; Esc schließt; nicht für reine Information.
- **Toast** (ein System für alles, `lib/toastStore.ts` + `components/Toaster.tsx`): oben rechts unterhalb der Kopfzeile (verdeckt die
  Seitenaktionen nicht), Varianten `success`/`info`/`warning`/`error`. Dauer 4 s / 4 s / 8 s, Fehler bleiben bis zum Schließen. Hover und
  Fokus halten die Zeit an. Gleiche Meldung innerhalb von 5 s wird zu „×3“ zusammengefasst, höchstens 4 sichtbar (Rest wartet,
  „+n weitere“). Optional eine Aktion; Schließen per Knopf oder Esc (Fokus im Bereich). Region „Benachrichtigungen“, Fehler
  `role="alert"`, sonst `role="status"`; reduzierte Bewegung ohne Übergang. Aufruf auch ohne React: `toast.success(…)`.
  Der API-Client meldet Fehler von Schreibzugriffen selbst (deutsche Texte, 5xx ohne Server-Detail; `silent` / `what` pro Aufruf).
  **Bleibt inline:** Feldfehler (Formulare, Passwortwechsel, Anmeldung), Zustände, die bestehen bleiben (Leer-/Fehlerzustände mit
  „Erneut versuchen“, Ladefehler einer Seite). Toast nie als einzige Quelle für etwas, das man später noch braucht.
- **Leerzustände:** sagen, was fehlt und was als Nächstes zu tun ist, mit einer Aktion („Agent hinzufügen“). **Fehlerzustände:**
  Ursache in einem Satz, „Erneut versuchen“, Stand der Daten (z. B. „Daten von vor 5 Min.“) bleibt sichtbar.
- **Details-Block:** Begründungen einer CVE-Bewertung per `<details>`. **Kleine Details:** relative Zeit mit absolutem `title` und
  `<time datetime>`; Kernel `6.8.0-31 → 6.8.0-35` bei laufend ≠ neueste; Token nur einmal sichtbar mit „Kopieren“;
  Nullwerte gedämpft statt farbig.
- **Live-Anzeige:** Punkt-Icon + Text „Live“ (verbunden) / „Getrennt, verbinde neu …“; Änderungen aktualisieren die Zeile ohne Sprung
  (`aria-live="polite"` nur für Zusammenfassungen, nicht für jede Zeile).

## Host-Seite

- Die CVE-Liste ist so hoch wie ihr Inhalt (Zeilenhöhe × Anzahl), höchstens Fensterhöhe minus Kopf und Kacheln
  (`clamp(12rem, 100dvh − 22rem, 56rem)`); erst darüber scrollt sie innen (ab 60 Zeilen virtualisiert). Der Platzhalter beim
  Laden nutzt die Zahl aus den Kopfzahlen, damit nichts springt.
- Ab 1280 px (Breakpoint `hd`; bei großer Schrift erst, wenn der Inhalt mindestens 60 rem breit ist: Variante `side`) steht
  rechts die mitlaufende Spalte „Host-Details“ (20 rem), darunter derselbe Inhalt als
  aufklappbarer Abschnitt unter den Kacheln. Die drei Kacheln (Offen, Neustart nötig, Gefixt; bei Proxmox-Kernel zusätzlich „Manuell prüfen“) sind gleich groß: ab 1280 px nebeneinander,
  640–1279 px 2×2, darunter eine Spalte; „Unbekannt“ bleibt bei 0 sichtbar, aber gedämpft.
- Ab 1600 px (`wide`) kommen Fix-Version (Offen), Paket und Quelle als Spalten dazu; die Beschreibung behält `1fr`.
  Unter 768 px oder wenn die Liste schmaler als 40 rem ist (große Schrift) ist die Zeile gestapelt; die Zeilenhöhe wächst
  mit der Schriftgröße (bei 16 px 32 bzw. 64 px).
- „Fix im Archiv“: Tooltip und Detaildialog nennen den Weg (`sudo apt update && sudo apt upgrade`, danach Neustart bei
  Kernel); es wird nichts ausgeführt. Die Daten nennen das Quell-Paket (z. B. `linux`) und die Fix-Version je Quelle, nicht aber
  den Namen des Binär-Kernelpakets im Archiv.

## Abruf-Stepper (CVE-Quellen)

- Sechs Schritte (Verbinden, Herunterladen, Auswerten, Speichern, Hosts prüfen, Fertig) als `<ol>` in einer Gruppe
  „Abruf <Quelle>“; Zustand je Schritt zusätzlich als `sr-only`-Text, der aktuelle Schritt trägt `aria-current="step"`.
- Symbole sind eigene SVGs (`currentColor`): Haken, Kreuz, gestrichelter Kreis (übersprungen), drehender Ring (aktiv),
  leerer Kreis (offen). Farbe ist nie der einzige Hinweis. Bei `prefers-reduced-motion` stehen Ring und Puls still.
- Mini-Stepper in der Tabellenzeile: sechs Segmente plus aktueller Schritt als Text; die Schaltfläche klappt die Details auf.
- Erfolg: Zusammenfassung als Toast, Details klappen nach 5 s ein. Fehlschlag: Details bleiben mit Meldung und
  „Erneut versuchen“, bis sie geschlossen werden.

## Profilbild

Kreis, 28 px in der Seitenleiste (48 px in den Einstellungen), `alt=""` bzw. `aria-hidden` (dekorativ; der Name steht daneben oder als
Tooltip). Initialen auf den Tokens `--av-1` … `--av-6` mit `--av-fg`; Kontrast ≥ 4,5:1 (Test liest die Tokens). Eigenes Bild nur von
`/api/v1/auth/avatar`, bei Ladefehler fallen die Initialen ein.

## Barrierefreiheit

- Text ≥ 4,5:1 (Tabellen oben), UI-Ränder/Icons ≥ 3:1, Fokusring auf allem Fokussierbaren.
- Vollständig per Tastatur bedienbar: „Zum Inhalt springen“, Seitenleiste mit Pfeil-/Tab-Navigation, Dialoge mit Fokusfalle,
  `aria-current`, `aria-sort`, `aria-live` für Rückmeldungen, Tabellen mit `<caption>` (visuell versteckt).
- Statusinformation nie nur über Farbe. Zielgröße 32 px (Touch 44 px) plus Abstand. Kein horizontaler Seitenüberlauf bei 390–1920 px und 200 % Zoom.
- Hell/Dunkel folgt dem System, umschaltbar (Einstellungen, wird gemerkt); `prefers-reduced-motion` beachtet.

## Texte

Deutsch, präzise, Aussagesatz oder Imperativ. Beispiele: „Noch kein Report“, „Neustart nötig“, „wartet auf Agent …“,
„Token wird nicht erneut angezeigt“, „Fix angekündigt (voraussichtlich in 7.0.0-43.43)“. Keine Ausrufezeichen, kein Emoji, keine Anrede.

## Watchlist-Markierung (v2.2)

Die ganze Zeile einer beobachteten CVE trägt einen leichten Akzentverlauf mit 1-px-Rand (4 px Radius). Es ist der einzige Verlauf der Oberfläche; alle anderen Flächen bleiben flach, es gibt kein Gittermuster.

| Token | Hell | Dunkel |
| --- | --- | --- |
| `--watch-bg-from` (links) | Akzent `#2a5bb8` 10 % | Akzent `#7ea6e8` 11 % |
| `--watch-bg-to` (rechts) | Akzent 0 % | Akzent 0 % |
| `--watch-border` | Akzent 32 % | Akzent 34 % |

Der Stern in der schmalen ersten Spalte ist zugleich der Schalter (`aria-label` und Tooltip „Beobachten“ / „Nicht mehr beobachten“, sichtbarer Fokus, 32 px Desktop, 44 px unter 768 px). Gefüllter Stern plus Rand tragen die Information, die Farbe allein nicht.
Hover und Fokus der Zeile legen `sunk` 60 % über den Verlauf. Der Verlauf ist statisch; es gibt keine Animation, `prefers-reduced-motion` ändert nichts.

Gemessener Kontrast auf dem dunkelsten Verlaufspunkt (links, Zeilenhintergrund = Seitenfläche + Verlauf), Hover in Klammern:

| Text | Hell | Dunkel |
| --- | --- | --- |
| `text` | 13.5 (14.1) | 12.0 (12.3) |
| `text-2` | 6.6 (6.9) | 6.7 (6.9) |
| `text-3` | 4.68 (4.90) | 4.72 (4.84) |
| Akzent/Links | 5.2 (5.4) | 6.1 (6.2) |
| `crit` | 5.9 (6.2) | 6.3 (6.5) |
| `warn` | 5.7 (6.0) | 7.9 (8.1) |
| `unknown` | 6.1 (6.4) | 7.4 (7.6) |

Alle Werte liegen über 4.5:1 (schwächster: `text-3` hell, 4.68).

## Benutzerseite und Rechtevorschau (v2.3)

Menüpunkt „Benutzer“ (Symbol `users`, zwischen Agents und Benachrichtigungen) nur mit `users.manage`; Direktaufruf ohne Recht
zeigt eine 403-Seite (`role="alert"`, Link zur Übersicht). Die Seite hat Tabs (`role="tablist"`, Pfeiltasten, Tab-Stop nur auf
dem aktiven Tab): *Benutzer*, *OIDC*, *Aktivität*. Tabellen wie Agents: `tbl stack-lg`, Zeilen ≤ 56 px, keine Klickfläche
auf der Zeile, Aktionen nebeneinander (Hauptaktion „Bearbeiten“/„Freigeben“ plus „…“-Menü), Avatar-Platzhalter 20 px,
Status als Chip mit Symbol und Text (aktiv / gesperrt / wartet auf Freigabe), mobil gestapelt mit 44-px-Zielen.
Dialoge nutzen `Dialog`/`ConfirmDialog` mit X-Knopf (`aria-label="Schließen"`); nur der Dialog mit dem Einmalpasswort hat bewusst
keinen X und kein Esc, weil der Wert nur einmal sichtbar ist. Die **Rechtevorschau** (`RolePreview`) listet je Recht Symbol
(Haken bzw. gestrichelter Kreis) **und** Text „darf“ / „darf nicht“, am Ende „Kann Geheimnisse sehen: nein“; der Bereich ist
per Tastatur scrollbar. Unter dem Formular steht die Zusammenfassung „Benutzer <Name> wird mit der Rolle <Rolle> angelegt.“.
Schreibaktionen ohne Recht werden ausgeblendet (nie nur deaktiviert); der Server bleibt maßgeblich.
