# Review der Design-Skills (Schritt A2)

Stand: vor Beginn der UI-Überarbeitung (Branch `feat/ui-v2`). Skills dienen nur als **Gestaltungsreferenz**;
bei Konflikten gilt `web/DESIGN.md` (v2).

## 1. Ergebnis in Kürze

| Repository | Skills dort | Installiert | Entfernt / nicht übernommen |
|---|---|---|---|
| `Prisma-Labs-Dev/apple-skills` | 34 (+5 deaktivierte) | **1** (`hig`, gekürzt) | 33 + 5 deaktivierte |
| `dpearson2699/swift-ios-skills` | 86 | **0** | 86 |

Der Inhalt von Prisma-Labs `hig` wurde nicht per `npx skills add`, sondern per `git clone --depth 1 --sparse`
(nur `skills/hig`, Commit `498626005e65783ebe8570a103b2335cf397768c`) bezogen und nach `.claude/skills/hig`
kopiert. `npx` wurde nicht ausgeführt, global wurde nichts installiert.

## 2. Warum nur `hig`

Sichtung beider Repos über die GitHub-API (Dateilisten, keine Ausführung):

- **apple-skills:** Alle Skills außer `hig` sind Swift/iOS/macOS-spezifisch (swiftui, uikit, swiftdata, storekit,
  healthkit, widgetkit, ios-liquid-glass, …). Zusätzlich liegen im Repo Skripte: `scripts/apple-docs/*.ts`
  (Netzwerkabruf), `scripts/*.sh` und Shell-Templates in `guide-macos-spm-packaging` (Signieren/Notarisieren).
  → nichts davon passt zu einer Next.js-Web-UI, Skripte/Netzwerk sind ausgeschlossen.
- **swift-ios-skills:** 86 Framework-Skills (…kit, swiftui-*), teils mit Python-Skripten
  (`ios-ettrace-performance`, `ios-memgraph-analysis`). `ios-accessibility` habe ich angelesen: reine
  SwiftUI/UIKit/AppKit-Umsetzung (Modifier, Rotors, Switch Control, Assistive Access); die plattformneutralen
  Grundsätze (Name/Rolle/Wert/Zustand, nie nur Farbe/Gesten) stehen schon in `hig/accessibility.md` und in
  `DESIGN.md`. → nicht übernommen.
- `hig` ist reines Markdown (51 Dateien, keine ausführbaren Dateien, keine Symlinks) und enthält plattformneutrale
  Grundsätze zu Buttons, Formularen, Listen, Rückmeldung, Barrierefreiheit.

## 3. Prüfung von `hig`

- **Gelesen:** `SKILL.md` vollständig. Von den übernommenen Seiten die Leitsätze (fett gesetzte Regeln) von
  buttons, lists-and-tables, text-fields, feedback, progress-indicators, sidebars, settings, searching, alerts,
  toggles, segmented-controls, accessibility, color, motion, layout. Alle 51 Dateien wurden maschinell geprüft;
  die übrigen Seiten wurden nicht Zeile für Zeile gelesen.
- **Maschinelle Prüfung (alle 51 Dateien):** keine HTML-Kommentare, keine Zero-Width-/Bidi-/Steuerzeichen,
  keine Base64-Blöcke (die Treffer waren Bild-URLs), keine ausführbaren Dateien, keine Symlinks, keine
  `<script>`-Tags, keine Phrasen, die einen Agenten ansprechen (außer dem Hinweis in `*.videos.md` zu
  „agent context“). Externe Links: 503 Bild-URLs auf `docs-assets.developer.apple.com`, ~190 Links auf
  `developer.apple.com`, einzelne auf `support.apple.com`, `help.apple.com`, `github.com`, `w3.org`.
- **Auffälligkeit in `SKILL.md`:** Abschnitt „Fetching More Docs“ weist an, fehlende Seiten über den
  Drittanbieter-Spiegel `sosumi.ai` aus dem Netz zu laden, und verweist auf weitere installierte Skills.
  → **entfernt** (Netzwerkzugriff). Zusätzlich im Frontmatter `context: fork` und `agent: Explore` entfernt
  (ändert das Ausführungsverhalten), Bash-Beispielblock (`grep` auf lokale Dateien) in Prosa belassen,
  Sektionen „Haptic Feedback Types“, „Safe Areas“ und WWDC/Liquid-Glass-Quellen gestrichen.
- **Änderungen an den Seiten:** nur Markdown-Bilder (externe Bild-URLs) entfernt; Text unverändert.

## 4. Dateien

**Übernommen (21):** accessibility, alerts, buttons, charts, color, feedback, layout, lists-and-tables, menus,
modality, motion, pickers, popovers, progress-indicators, searching, segmented-controls, settings, sidebars,
text-fields, toggles, typography.

**Entfernt (29):**

| Datei(en) | Grund |
|---|---|
| `*.videos.md` (accessibility, alerts, app-icons, buttons, materials, playing-haptics, scroll-views, sf-symbols, sheets, tab-bars) | nur Video-Links |
| app-icons, home-screen-quick-actions, launching, status-bars, designing-for-ios | App-/Geräte-spezifisch |
| tab-bars, navigation-bars, toolbars, sheets, action-sheets, activity-views, scroll-views | iOS-Navigations-/Präsentationsmuster (für Web nicht übertragen) |
| materials, sf-symbols | Liquid Glass/Vibrancy bzw. SF Symbols; widerspricht „kein Glassmorphism, eigene Icons“ |
| playing-haptics | Haptik |
| onboarding, sliders, steppers | für die Ops-Konsole ohne Nutzen |
| hig-index | Index auf Seiten, die nicht mehr vorliegen |

Behalten, obwohl teils Apple-lastig: `color`, `typography`, `layout`, `pickers`, `sidebars`. Sie enthalten
iOS-/Liquid-Glass-Passagen; übernommen wird nur das Plattformneutrale (siehe Regeln), Apple-Werte
(Systemfarben, Punktgrößen, Dynamic Type) werden **nicht** übertragen.

## 4a. Konfliktfälle (gelten nicht für das Web)

- „Avoid full-width buttons“ (layout) / „Prefer buttons that span the width of the screen“ (buttons): Auf dem
  Web entscheiden Tabellen-/Formularkontext; mobil sind volle Breiten für primäre Aktionen zulässig.
- „Prefer system-defined colors“, „Avoid hard-coding system color values“: nicht übertragbar; eigene Tokens in
  DESIGN.md.
- „Consider using a tab bar first“ (sidebars): Tab-Bars werden nicht verwendet; Seitenleiste ist vorgegeben.
- „In general, prefer circular or capsule-shape buttons“ (buttons): nicht übernommen (Ops-Konsole, dichte Tabellen).
- Alternierende Zeilenfarben in Tabellen: nicht übernommen; stattdessen Trennlinien und Hover.

## 5. Übernommene Regeln (werden in DESIGN.md v2 formuliert)

**Buttons**
- Eine primäre Aktion pro Ansicht/Bereich, Hervorhebung über Stil, nicht über Größe.
- Destruktive Aktion nie als primäre/vorausgewählte Aktion; Bestätigung benennt das Objekt; „Abbrechen“ ist
  der sichere Standard.
- Beschriftung = Verb + Objekt („Token erneuern“), kurze Texte statt reiner Icons bei unklarer Bedeutung;
  „…“ nur, wenn ein weiterer Schritt folgt.
- Jeder Button hat Press-/Fokus-/Disabled-Zustand; bei längeren Aktionen Fortschrittsanzeige am Button.
- Mindest-Trefferfläche: Touch 44×44 px, Desktop mind. 32 px Höhe; Abstand zwischen Controls zählt wie Größe.

**Abstände / Layout**
- Zusammengehörendes gruppieren (Abstand vor Linie), Wichtiges bekommt Platz und Position oben/links.
- Bedienelemente vom Inhalt abheben (eigene Fläche), an gemeinsamen Kanten ausrichten, Progressive
  Disclosure statt alles anzeigen. 4-px-Raster.
- Layout hält Textvergrößerung stand (rem, kein fester Zeilenabstand in px).

**Zustände / Rückmeldung**
- Jede Aktion bekommt sichtbare Rückmeldung; Fehler sagen, warum etwas nicht geht und was als Nächstes zu tun ist.
- Alerts/Dialoge sparsam: nur für kritische, unumkehrbare Aktionen; kein Dialog bei rückgängig machbaren
  Aktionen; Titel beschreibt die Lage knapp; Buttons benennen die Aktion (kein „OK“).
- Fortschritt: bestimmt statt unbestimmt, wenn messbar; konstanter Ort; Hinweistext nur mit Mehrwert;
  Hintergrundaktualisierungen automatisch.
- Rückmeldung nie nur über Farbe oder Ton.

**Typografie**
- Wenige Größenstufen, Hierarchie über Größe/Gewicht, Gewicht beeinflusst Lesbarkeit; große Texte bleiben lesbar.

**Listen/Tabellen**
- Kurze Zeilentexte, beschreibende Spaltenköpfe, Sortierung per Klick auf den Kopf, gekürzten Text per Tooltip
  zugänglich halten, Zeilenzahl begrenzen.

**Formulare / Schalter**
- Textfelder nur wenn nötig, Größe passend zur erwarteten Eingabe, Hinweistext/Label, Passwortfelder verdeckt,
  Validierung zum passenden Zeitpunkt, sinnvolle Tab-Reihenfolge.
- Einzelne Ein/Aus-Einstellung = Checkbox oder klar beschrifteter Schalter; mehr als zwei exklusive Optionen =
  Radiogruppe; Zustandsunterschied deutlich.
- Segmentierte Steuerung (für „Liste | Matrix“): wenige, gleich große Segmente, Substantive als Beschriftung.
- Einstellungen: wenige, sinnvolle Voreinstellungen; nichts abfragen, was sich anders ermitteln lässt.

**Seitenleiste**
- Höchstens zwei Hierarchieebenen, kurze Gruppenüberschriften, nichts Kritisches am unteren Rand,
  auf schmalen Fenstern automatisch einklappen.

**Barrierefreiheit**
- Kontrast Text ≥ 4.5:1, große/fette Texte ≥ 3:1 (Apple-Tabelle deckt sich mit WCAG AA).
- Information nie nur über Farbe; Bewegung optional und kurz, selten bei häufigen Interaktionen
  (`prefers-reduced-motion`); schnelles Blinken vermeiden.
- Alternativen zu Gesten; Controls ausreichend groß und mit ausreichendem Abstand.
