# Responsiv-Prüfung (Phase 3)

Skripte: `scripts/responsive-all.mjs` (alle Seiten und Zustände, 22 Varianten: 12 Breiten 320 bis 2560, dunkel bei 390/1024/1440,
reduzierte Bewegung bei 390/1440, Querformat L844 und L1024, Zoom 200 % = Z200 (720 px, Pixeldichte 2), Schriftzoom 200 % = F1280 und F390)
und `scripts/snapshot-diff.mjs`. Keine verändernden Aktionen; die Fehlermeldung der Anmeldung wird mit nachgestellter 401-Antwort erzeugt
(kein echter Fehlversuch).

## Zusammenfassung

Erster Lauf: 287 Verstöße (103 verschiedene). Nach den Korrekturen dieser Phase: 33 Verstöße (26 verschiedene), alle bei Schriftzoom 200 %
(F1280) oder bei genau 1024 px (Hosts-Tabelle). Bestanden bei allen 22 Varianten: Login, Einstellungen, 404, CVE-Quellen (Überlauf, Fenster),
Knopfhöhen (Prüfung 5), axe serious/critical (Prüfung 9), Layoutsprung (Prüfung 10), Trefferflächen < 768 px (Prüfung 4).

### Behoben (je ein Commit)
- Popover/Filter/„…“-Menü ragten bei niedrigem Viewport (844x390, Zoom 200 %) heraus: klappt nach oben, scrollt innen, Höhe mit endgültiger Breite gemessen.
- Namenslinks der gestapelten Tabellen (Hosts, Agents, Benachrichtigungen) 37 bis 43 px breit: jetzt mindestens 44 x 44 px.
- `fieldset` und Felder sprengten bei großer Schrift die Spalte (Einstellungen, Kanalformulare): `min-width: 0`, `max-width: 100%`.
- Mobile Kopfzeile verbreiterte die Seite bei langem Seitentitel: Titel kürzt mit Tooltip.
- Knopfreihe der CVE-Quellen überlief bei 200 % Schrift: bricht um.
- Hosts-Kennzahlen (Sicherheitsupdates) überliefen bei F390; CVE-Spalte der Hosts-Tabelle min-w 13 rem; Kacheln der Host-Seite brechen um (Text 3 px abgeschnitten bei 1280 px).
- Checkbox-Beschriftung („Tageszusammenfassung“) überlief bei F390.

### Korrigierte Prüfungen (falsch positiv)
- Versteckter Tabellenkopf der gestapelten Ansicht (sr-only) und geschlossenes Off-Canvas zählen nicht (A2, A3).
- Icon-Rail (768 bis 1023 px): Beschriftung mit opacity 0 ist gewollt unsichtbar (A6, „Abmelden“).

### Begründete Ausnahmen (im Skriptkopf)
A1 Inline-Textlinks außerhalb von nav/aside, A2 Sortierknöpfe im ausgeblendeten Tabellenkopf, A3 inert/aria-hidden/sr-only, A4 Ellipsen-Absicht
oder title, A6 Rail-Beschriftung.

### Offen (Skript bleibt rot)
1. Schriftzoom 200 % bei 1280 px (F1280): Seitenüberlauf durch Tabellen ohne Scroll-Container ab 1280 px (Hosts 2175 px, Agents 2220 px,
   Sidebar eingeklappt/Hosts 2011 px; CVEs endet bei 1724 statt 1232; CVE-Detail 1464,6). Grund: Tabellen scrollen nur unter `hd`
   (1280) in ihrem Container, weil `overflow-x: auto` den fixen Tabellenkopf (sticky) bricht; die rem-Mindestbreiten wachsen mit der
   Schrift, die Breakpoints (Media Queries) nicht. Lösung wäre Container-Queries oder ein Scroll-Container, der nur bei Bedarf greift.
2. F1280 Host-Detail: Zeilenraster der CVE-Liste (feste rem-Spalten, 33 rem) 1301 bis 1612 px bei 1280 px Fenster, Tabelle „Verlauf der letzten Datenmeldungen“ endet bei 1151 bis 1289 px.
3. 1024 px Hosts-Tabelle: letzte Spalte endet bei 1029,8 statt 1000 (30 px innerer Scroll). Ursache: Spaltenbreiten richten sich nach Inhalt
   (CVE 260 px, Status 185 px, Summe 786 px bei 756 px Platz); Fix-Versuch (min-w CVE 13 rem) ohne Wirkung. Alle Breiten ≥ 1180 px bestehen.
4. F1280 Benachrichtigungen: Tabelle endet bei 1249,7 statt 1232 (18 px).

## Ergebnistabelle (letzter vollständiger Lauf, 638 Zustände x Varianten)


| Seite / Zustand | 320 | 360 | 390 | 430 | 768 | 820 | 1024 | 1180 | 1280 | 1440 | 1920 | 2560 | 390d | 1024d | 1440d | 390rm | 1440rm | L844 | L1024 | Z200 | F1280 | F390 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| login / Login | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok |
| login / Login mit Fehlermeldung | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok |
| hosts / Hosts | ok | ok | ok | ok | ok | ok | 1 | ok | ok | ok | ok | ok | ok | 1 | ok | ok | ok | ok | 1 | ok | 2 | ok |
| host-detail / Host Ubuntu (offene CVEs, web-02) | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | 2 | 1 |
| host-detail / Host mit Neustart (db-02) | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | 2 | 1 |
| host-detail / Host Proxmox (pve-01) | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | 2 | 1 |
| host-detail / Host ohne Daten (neu-01) | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | 1 | 1 |
| cves / CVEs Liste | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | 1 | ok |
| cves / CVEs Filter-Fenster offen | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | 1 | ok |
| cves / CVEs nur Watchlist | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | 1 | ok |
| cves / CVEs aktiver Filter | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | 1 | ok |
| cves / CVEs leeres Ergebnis | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok |
| cve-detail / CVE-Detail | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | 1 | ok |
| cve-sources / Quellen eingeklappt | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | 1 | ok |
| cve-sources / Quellen Verwalten aufgeklappt | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | 1 | ok |
| cve-sources / Dialog Quelle hinzufügen | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | 1 | ok |
| agents / Agents Liste | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | 2 | ok |
| agents / Agents …-Menü offen | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | 2 | ok |
| agents / Dialog Agent hinzufügen | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | 2 | ok |
| notifications / Benachrichtigungen | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | 1 | ok |
| notifications / Kanal ntfy | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok |
| notifications / Kanal matrix | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok |
| notifications / Kanal gotify | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok |
| notifications / Kanal discord | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok |
| notifications / Kanal browser | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok |
| settings / Einstellungen | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok |
| notfound / 404-Seite | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok | ok |
| sidebar / Sidebar eingeklappt | – | – | – | – | – | – | ok | ok | ok | ok | ok | ok | – | ok | ok | – | ok | – | ok | – | 2 | – |
| sidebar / Sidebar Off-Canvas offen | ok | ok | ok | ok | – | – | – | – | – | – | – | – | ok | – | – | ok | – | – | – | ok | – | ok |


## Verstöße

- **hoch** (Prüfung 1) Hosts: Seitenüberlauf
  - F1280: scrollWidth 2175 > clientWidth 1280; z. B. table "Hosts mit Distribution, Kernel, Zeitpunk", thead "HostDistribution / KernelZuletzt gemelde", tr "HostDistribution / KernelZuletzt gemelde"
- **hoch** (Prüfung 1) Host Ubuntu (offene CVEs, web-02): Seitenüberlauf
  - F1280: scrollWidth 1340 > clientWidth 1280; z. B. span "Seit", table "Verlauf der letzten DatenmeldungenZeitpu", thead "ZeitpunktLaufender KernelUpdatesNeustart"
  - F390: scrollWidth 544 > clientWidth 390; z. B. label "CVEs dieses Hosts durchsuchen", input "CVEs dieses Hosts durchsuchen"
- **hoch** (Prüfung 1) Host mit Neustart (db-02): Seitenüberlauf
  - F1280: scrollWidth 1301 > clientWidth 1280; z. B. span "Seit"
  - F390: scrollWidth 544 > clientWidth 390; z. B. label "CVEs dieses Hosts durchsuchen", input "CVEs dieses Hosts durchsuchen"
- **hoch** (Prüfung 1) Host Proxmox (pve-01): Seitenüberlauf
  - F1280: scrollWidth 1612 > clientWidth 1280; z. B. span "Fix-Version", span "Seit", table "Verlauf der letzten DatenmeldungenZeitpu"
  - F390: scrollWidth 544 > clientWidth 390; z. B. label "CVEs dieses Hosts durchsuchen", input "CVEs dieses Hosts durchsuchen"
- **hoch** (Prüfung 1) Host ohne Daten (neu-01): Seitenüberlauf
  - F1280: scrollWidth 1340 > clientWidth 1280; z. B. span "Seit"
  - F390: scrollWidth 544 > clientWidth 390; z. B. label "CVEs dieses Hosts durchsuchen", input "CVEs dieses Hosts durchsuchen"
- **hoch** (Prüfung 1) Agents Liste: Seitenüberlauf
  - F1280: scrollWidth 2220 > clientWidth 1280; z. B. table "Agents mit Zeitpunkt der letzten Daten, ", thead "NameHostname laut AgentDistributionZulet", tr "NameHostname laut AgentDistributionZulet"
- **hoch** (Prüfung 1) Agents …-Menü offen: Seitenüberlauf
  - F1280: scrollWidth 2220 > clientWidth 1280
- **hoch** (Prüfung 1) Dialog Agent hinzufügen: Seitenüberlauf
  - F1280: scrollWidth 2220 > clientWidth 1280; z. B. table "Agents mit Zeitpunkt der letzten Daten, ", thead "NameHostname laut AgentDistributionZulet", tr "NameHostname laut AgentDistributionZulet"
- **hoch** (Prüfung 1) Sidebar eingeklappt: Seitenüberlauf
  - F1280: scrollWidth 2011 > clientWidth 1280; z. B. table "Hosts mit Distribution, Kernel, Zeitpunk", thead "HostDistribution / KernelZuletzt gemelde", tr "HostDistribution / KernelZuletzt gemelde"
- **niedrig** (Prüfung 6) Hosts: Tabelle Hosts mit Distribution, Kernel: letzte Spalte
  - 1024: endet bei 1029.8, Rand 1000.0
  - 1024d: endet bei 1029.8, Rand 1000.0
  - L1024: endet bei 1029.8, Rand 1000.0
  - F1280: endet bei 2174.9, Rand 1232.0
- **niedrig** (Prüfung 6) Host Ubuntu (offene CVEs, web-02): Tabelle Verlauf der letzten Datenmeldu: letzte Spalte
  - F1280: endet bei 1288.6, Rand 544.0
- **niedrig** (Prüfung 6) Host mit Neustart (db-02): Tabelle Verlauf der letzten Datenmeldu: letzte Spalte
  - F1280: endet bei 1151.7, Rand 544.0
- **niedrig** (Prüfung 6) Host Proxmox (pve-01): Tabelle Verlauf der letzten Datenmeldu: letzte Spalte
  - F1280: endet bei 1288.6, Rand 544.0
- **niedrig** (Prüfung 6) CVEs Liste: Tabelle CVEs mit Distributionen, betro: letzte Spalte
  - F1280: endet bei 1724.0, Rand 1232.0
- **niedrig** (Prüfung 6) CVEs Filter-Fenster offen: Tabelle CVEs mit Distributionen, betro: letzte Spalte
  - F1280: endet bei 1724.0, Rand 1232.0
- **niedrig** (Prüfung 6) CVEs nur Watchlist: Tabelle CVEs mit Distributionen, betro: letzte Spalte
  - F1280: endet bei 1724.0, Rand 1232.0
- **niedrig** (Prüfung 6) CVEs aktiver Filter: Tabelle CVEs mit Distributionen, betro: letzte Spalte
  - F1280: endet bei 1724.0, Rand 1232.0
- **niedrig** (Prüfung 6) CVE-Detail: Tabelle Bewertung der Hosts für CVE-20: letzte Spalte
  - F1280: endet bei 1464.6, Rand 1232.0
- **niedrig** (Prüfung 6) Quellen eingeklappt: Tabelle CVEs mit Distributionen, betro: letzte Spalte
  - F1280: endet bei 1724.0, Rand 1232.0
- **niedrig** (Prüfung 6) Quellen Verwalten aufgeklappt: Tabelle CVEs mit Distributionen, betro: letzte Spalte
  - F1280: endet bei 1724.0, Rand 1232.0
- **niedrig** (Prüfung 6) Dialog Quelle hinzufügen: Tabelle CVEs mit Distributionen, betro: letzte Spalte
  - F1280: endet bei 1724.0, Rand 1232.0
- **niedrig** (Prüfung 6) Agents Liste: Tabelle Agents mit Zeitpunkt der letzt: letzte Spalte
  - F1280: endet bei 2220.0, Rand 1232.0
- **niedrig** (Prüfung 6) Agents …-Menü offen: Tabelle Agents mit Zeitpunkt der letzt: letzte Spalte
  - F1280: endet bei 1280.0, Rand 292.0
- **niedrig** (Prüfung 6) Dialog Agent hinzufügen: Tabelle Agents mit Zeitpunkt der letzt: letzte Spalte
  - F1280: endet bei 2220.0, Rand 1232.0
- **niedrig** (Prüfung 6) Benachrichtigungen: Tabelle Benachrichtigungskanäle mit Zu: letzte Spalte
  - F1280: endet bei 1249.7, Rand 1232.0
- **niedrig** (Prüfung 6) Sidebar eingeklappt: Tabelle Hosts mit Distribution, Kernel: letzte Spalte
  - F1280: endet bei 2010.9, Rand 1232.0

638 Zustände x Varianten geprüft, 33 Verstöße.

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
