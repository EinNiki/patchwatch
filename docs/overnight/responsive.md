# Responsiv-Prüfung (Phase 3)

Skripte: `scripts/responsive-all.mjs` (alle Seiten und Zustände, 22 Varianten: 12 Breiten 320 bis 2560, dunkel bei 390/1024/1440,
reduzierte Bewegung bei 390/1440, Querformat L844 und L1024, Zoom 200 % = Z200 (720 px, Pixeldichte 2), Schriftzoom 200 % = F1280 und F390)
und `scripts/snapshot-diff.mjs`. Keine verändernden Aktionen; die Fehlermeldung der Anmeldung wird mit nachgestellter 401-Antwort erzeugt
(kein echter Fehlversuch).

## Zusammenfassung

Erster Lauf: 287 Verstöße (103 verschiedene). Nach der ersten Korrekturrunde: 33 Verstöße (26 verschiedene), alle bei Schriftzoom 200 %
(F1280, F390) oder bei genau 1024 px (Hosts-Tabelle). Nach der zweiten Runde (Eskalation): **0 Verstöße**, `responsive-all.mjs` endet mit
Exit 0 (voller Lauf, 638 Zustände x Varianten, 1154 s).

### Behoben (je ein Commit)
- Popover/Filter/„…“-Menü ragten bei niedrigem Viewport (844x390, Zoom 200 %) heraus: klappt nach oben, scrollt innen, Höhe mit endgültiger Breite gemessen.
- Namenslinks der gestapelten Tabellen (Hosts, Agents, Benachrichtigungen) 37 bis 43 px breit: jetzt mindestens 44 x 44 px.
- `fieldset` und Felder sprengten bei großer Schrift die Spalte (Einstellungen, Kanalformulare): `min-width: 0`, `max-width: 100%`.
- Mobile Kopfzeile verbreiterte die Seite bei langem Seitentitel: Titel kürzt mit Tooltip.
- Knopfreihe der CVE-Quellen überlief bei 200 % Schrift: bricht um.
- Hosts-Kennzahlen (Sicherheitsupdates) überliefen bei F390; CVE-Spalte der Hosts-Tabelle min-w 13 rem; Kacheln der Host-Seite brechen um (Text 3 px abgeschnitten bei 1280 px).
- Checkbox-Beschriftung („Tageszusammenfassung“) überlief bei F390.

Zweite Runde:
- F1280, Tabellen (Hosts 2175 px, Agents 2220 px, eingeklappte Seitenleiste 2011 px, CVEs bis 1724, CVE-Detail bis 1464,6 statt 1232):
  Ursache waren px-Media-Queries als Umschaltpunkte, während die Mindestbreiten in rem mit der Schrift wachsen. Tabellen stapeln jetzt
  zusätzlich, wenn ihr Behälter (`@container/tbl`) schmaler als 40 rem ist; Container-Queries rechnen rem mit der tatsächlichen
  Schriftgröße. Bei 16 px ist der Behälter ab 768 px mindestens 664 px breit, dort ändert sich nichts (Geometrievergleich aller
  Elemente in `main` bei 390 bis 2560 px, Seitenleiste offen und eingeklappt: gleich bis auf Zeitangaben). Kein `overflow-x` ab 1280 px,
  der feste Tabellenkopf bleibt.
- F1280, Host-Seite (CVE-Zeilen 1301 bis 1612 px, Verlauf bis 1289 statt 544): rechte Spalte „Host-Details“ nur noch, wenn der Inhalt
  mindestens 60 rem breit ist (`side`/`no-side`); die CVE-Liste nutzt die gestapelte Zeile auch unter 40 rem Listenbreite, Zeilenhöhe
  wächst mit der Schrift; Verlauf stapelt wie die übrigen Tabellen.
- 1024 px, Hosts-Tabelle (letzte Spalte bei 1029,8 statt 1000, Status-Chip abgeschnitten): Updates entfällt wie „Zuletzt gemeldet“
  zwischen 768 und 1279 px (vorher nur bis 1023). CVE (zwei feste Spalten) und Status (längster Chip) brauchen ihre Breite, Host und
  Distribution standen schon auf ihrer Mindestbreite.
- F1280, Benachrichtigungen (1249,7 statt 1232): Tabelle im Behälter `@container/tbl`, stapelt wie die übrigen.
- F390, Host-Seite (Seite 544 px breit): CVE-Suchfeld (16 rem) durch das Label auf die Zeilenbreite begrenzt.

### Korrigierte Prüfungen (falsch positiv)
- Versteckter Tabellenkopf der gestapelten Ansicht (sr-only) und geschlossenes Off-Canvas zählen nicht (A2, A3).
- Icon-Rail (768 bis 1023 px): Beschriftung mit opacity 0 ist gewollt unsichtbar (A6, „Abmelden“).
- Prüfung 6 bei gestapelten Tabellen ab 1024 px (gibt es erst seit dieser Runde, bei großer Schrift): Die Kopfzellen liegen in einem
  1-px-Ausschnitt nur für Screenreader und sind keine Spalten. Gemessen werden dann die sichtbaren Einträge (Zeilen), die ebenfalls am
  Inhaltsrand enden müssen (±1 px). Für Tabellen mit sichtbarem Kopf ist die Prüfung unverändert.

### Begründete Ausnahmen (im Skriptkopf)
A1 Inline-Textlinks außerhalb von nav/aside, A2 Sortierknöpfe im ausgeblendeten Tabellenkopf, A3 inert/aria-hidden/sr-only, A4 Ellipsen-Absicht
oder title, A6 Rail-Beschriftung.

### Offen
Keine Verstöße in den 22 Varianten. Außerhalb der Varianten (einzeln gemessen, Fenster 1280 px, Seitenleiste offen):
- Schrift 125 %: Hosts 1471 px, Agents 1470 px Seitenbreite; 150 %: Hosts 1700 px, Agents 1720 px (Seitenüberlauf). 175 % und 200 %:
  kein Überlauf. Ursache: Die Grenze von 40 rem greift bei 1012 px Behälter erst ab etwa 158 % Schrift; darunter gilt die
  Tabellenansicht mit den `hd`-Mindestbreiten (Hosts 58 rem, Agents 61 rem) ohne Scroll-Behälter. Unverändert gegenüber vorher (die neue
  Bedingung greift dort nicht). Möglicher Weg: je Umschaltpunkt eine eigene Container-Grenze (z. B. ab 1280 px stapeln unter 62 rem);
  nicht umgesetzt, weil es die Prüfvarianten nicht verlangen und die Grenze bei 16 px nur 5 px Abstand zur Fensterbreite 1280 mit
  klassischer Bildlaufleiste hätte.
- Auffällig, nicht Teil der Prüfungen: Chip-Höhe (`--chip-h` 22 px) und die CVE-Zelle der Hostliste (`text-[13px]`) sind in px und
  wachsen bei großer Schrift nicht mit (Text höher als die Chip-Fläche); „Keine Antwort seit …“ in der Agents-Tabelle bricht bei 1024 px
  Buchstabe für Buchstabe um (schmale Spalte, schon vorher so).

## Ergebnistabelle (letzter vollständiger Lauf, 638 Zustände x Varianten)

| Seite / Zustand | 320 | 360 | 390 | 430 | 768 | 820 | 1024 | 1180 | 1280 | 1440 | 1920 | 2560 | 390d | 1024d | 1440d | 390rm | 1440rm | L844 | L1024 | Z200 | F1280 | F390 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| login / Login | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok |
| login / Login mit Fehlermeldung | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok |
| hosts / Hosts | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok |
| host-detail / Host Ubuntu (offene CVEs, web-02) | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok |
| host-detail / Host mit Neustart (db-02) | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok |
| host-detail / Host Proxmox (pve-01) | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok |
| host-detail / Host ohne Daten (neu-01) | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok |
| cves / CVEs Liste | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok |
| cves / CVEs Filter-Fenster offen | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok |
| cves / CVEs nur Watchlist | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok |
| cves / CVEs aktiver Filter | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok |
| cves / CVEs leeres Ergebnis | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok |
| cve-detail / CVE-Detail | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok |
| cve-sources / Quellen eingeklappt | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok |
| cve-sources / Quellen Verwalten aufgeklappt | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok |
| cve-sources / Dialog Quelle hinzufügen | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok |
| agents / Agents Liste | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok |
| agents / Agents …-Menü offen | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok |
| agents / Dialog Agent hinzufügen | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok |
| notifications / Benachrichtigungen | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok |
| notifications / Kanal ntfy | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok |
| notifications / Kanal matrix | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok |
| notifications / Kanal gotify | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok |
| notifications / Kanal discord | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok |
| notifications / Kanal browser | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok |
| settings / Einstellungen | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok |
| notfound / 404-Seite | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok |
| sidebar / Sidebar eingeklappt | – | – | – | – | – | – | ok | ok | ok | ok | ok | ok | – | ok | ok | – | ok | – | ok | – | ok | – |
| sidebar / Sidebar Off-Canvas offen | ok | ok | ok | ok | – | – | – | – | – | – | – | – | ok | – | – | ok | – | – | – | ok | – | ok |

## Verstöße

Keine. 638 Zustände x Varianten geprüft, 0 Verstöße (Exit 0).

# Vergleich mit dem Design-Snapshot 2026-11-11

Toleranz 24 je Pixel, Schwelle 2 %. Größenunterschiede (Snapshot 950 px hoch, jetzt kürzere Seiten) zählen als abweichend und erhöhen den Wert um bis zu 5 %.

Toleranz je Pixel: 24 (größte Kanalabweichung), Schwelle 2 %.

| Bild | abweichende Pixel | Größe (Snapshot vs jetzt) |
|---|---|---|
| hosts-1440-light.png | 11.25 % (über Schwelle) | 1440x950 vs 1440x900 |
| host-detail-1440-light.png | 10.93 % (über Schwelle) | 1440x950 vs 1440x900 |
| cves-1440-light.png | 8.71 % (über Schwelle) | 1440x950 vs 1440x946 |
| agents-1440-light.png | 4.76 % (über Schwelle) | 1440x900 vs 1440x900 |
| settings-1440-light.png | 0.09 % | 1440x950 vs 1440x950 |
| notifications-1440-light.png | 4.94 % (über Schwelle) | 1440x900 vs 1440x900 |
| login-1440-light.png | 0.00 % | 1440x900 vs 1440x900 |
| hosts-390-light.png | 7.45 % (über Schwelle) | 390x950 vs 390x950 |
| host-detail-390-light.png | 13.26 % (über Schwelle) | 390x950 vs 390x950 |
| cves-390-light.png | 16.05 % (über Schwelle) | 390x950 vs 390x950 |
| agents-390-light.png | 6.68 % (über Schwelle) | 390x950 vs 390x950 |
| settings-390-light.png | 0.00 % | 390x950 vs 390x950 |
| notifications-390-light.png | 8.02 % (über Schwelle) | 390x950 vs 390x950 |
| login-390-light.png | 0.00 % | 390x844 vs 390x844 |
| hosts-1440-dark.png | 12.16 % (über Schwelle) | 1440x950 vs 1440x900 |
| host-detail-1440-dark.png | 13.39 % (über Schwelle) | 1440x950 vs 1440x900 |
| cves-1440-dark.png | 8.76 % (über Schwelle) | 1440x950 vs 1440x946 |
| agents-1440-dark.png | 4.87 % (über Schwelle) | 1440x900 vs 1440x900 |
| settings-1440-dark.png | 0.08 % | 1440x950 vs 1440x950 |
| notifications-1440-dark.png | 4.73 % (über Schwelle) | 1440x900 vs 1440x900 |
| login-1440-dark.png | 0.00 % | 1440x900 vs 1440x900 |
| hosts-390-dark.png | 8.86 % (über Schwelle) | 390x950 vs 390x950 |
| host-detail-390-dark.png | 12.16 % (über Schwelle) | 390x950 vs 390x950 |
| cves-390-dark.png | 14.91 % (über Schwelle) | 390x950 vs 390x950 |
| agents-390-dark.png | 6.83 % (über Schwelle) | 390x950 vs 390x950 |
| settings-390-dark.png | 0.00 % | 390x950 vs 390x950 |
| notifications-390-dark.png | 8.46 % (über Schwelle) | 390x950 vs 390x950 |
| login-390-dark.png | 0.00 % | 390x844 vs 390x844 |

20 von 28 über 2 %.

Einordnung:
- Login 0,00 %, Einstellungen 0,00 bis 0,09 %: unverändert.
- Hosts, Host-Detail, CVEs, Agents (4,7 bis 16 %): gewollte Änderungen dieser Nacht (Tabellen statt Karten, Knöpfe 32 px, Agents-Spalten, Kacheln,
  Quellenzeile) plus Daten (anderer Seed-Zeitpunkt, andere CVE-Zahlen, Zeitangaben); die Differenzbilder zeigen verschobene Zeilen, keine fehlenden Elemente.
- Benachrichtigungen (4,7 bis 8,5 %): Spaltenverschiebung der Tabelle (Zustand, Ereignisse) und Zeitangaben; keine fehlenden Elemente.
- Rückschritte: keine belegt, daher keine Änderung.
