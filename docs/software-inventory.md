# Software-Inventar

Unter **Software** werden alle gemeldeten Systempakete angezeigt, mit Suche nach
Paket, Quellpaket oder Host, Hostfilter und Seiten mit je 50 Einträgen. Auf jeder
Host-Seite führt **Software anzeigen** direkt zum passenden Filter.

## Aktivieren

In `/etc/patchwatch/agent.toml` setzen:

```toml
include_packages = true
```

Anschließend unter **Agents → Daten jetzt abrufen** eine neue Meldung anfordern.
Die Erfassung bleibt freiwillig. Der Agent meldet nur installierte dpkg-Pakete;
entfernte Pakete mit verbliebenen Konfigurationsdateien werden ausgefiltert.
Eine leere Liste entfernt alte Pakete. Eine fehlende Liste erhält den letzten
Stand, der sichtbar als veraltet markiert wird. Der Erfassungszeitpunkt liegt
getrennt vom letzten Host-Report in `hosts.packages_reported_at`.

## Sicherheitsbewertung

Der Debian-Import berücksichtigt alle Quellpakete. Auch Ubuntu-API-Antworten
werden ohne Kernelfilter abgerufen und ausgewertet. Migration 0027 setzt die
alten Import-Cursor zurück, damit der bisherige Umfang nicht als vollständiger
Softwareimport gilt. Vorhandene CVE-Daten bleiben erhalten.

Die Ubuntu-OVAL-Massendaten liefern weiterhin ausschließlich Kernel-Fixes. Im
Hybridmodus kommen Anwendungsdaten aus den neu abgefragten API-Seiten und der
Watchlist. Eine vollständige historische Abdeckung aller Ubuntu-Anwendungen ist
damit **noch nicht gegeben**. Fehlende Zuordnungen bleiben unbekannt.

Der Abgleich verwendet Distribution, Release und **Quellpaketversion** mit
dpkg-Versionsregeln, einschließlich Epoch und Backports. Eine Binärpaketversion
ersetzt keine fehlende Version eines anders benannten Quellpakets. Einträge
abgeschalteter oder gelöschter Quellen werden ignoriert. Veraltete Paketlisten
oder unbrauchbare Feeds liefern keinen bestätigten Fix; bekannte offene
Schwachstellen bleiben sichtbar.

- **Verwundbar:** mindestens eine bekannte Meldung betrifft die Version.
- **Bekannte Meldungen erledigt:** alle zugeordneten Meldungen sind behoben oder
  nicht zutreffend. Das bestätigt die installierten Pakete, nicht laufende Prozesse.
- **Nicht abschließend bewertet:** fehlende Zuordnung, unklare oder veraltete Daten.

In der aufgeklappten Meldungsliste stehen betroffene Paketversionen zuerst,
danach unklare Bewertungen und zuletzt behobene oder nicht zutreffende Meldungen.
Die Reihenfolge richtet sich nach der Bewertung der installierten Version.

Kernelpakete verweisen für die Bewertung auf die bestehende Host-Seite. Ein neu
installierter Kernel beweist nicht, dass der Fix bereits läuft. Die bestehenden
Host-Gesamtstatus und Benachrichtigungen beruhen weiterhin auf Kernel und Updates;
die zusätzliche Softwarebewertung wird beim Öffnen des Inventars berechnet.

Update-Kandidaten stammen aus der vorhandenen apt-Update-Liste des Reports. Diese
kann begrenzt oder nicht verfügbar sein; „Kein Kandidat gemeldet“ bedeutet deshalb
nicht zwingend, dass kein Update existiert.

## API und Erweiterungen

`GET /api/v1/software?host_id=1&q=nginx&limit=50&offset=0` liefert Pakete,
Gesamtzahl, Seitendaten und Erfassungszeiten der Hosts. `limit` ist auf 200 begrenzt.
Das Recht `hosts.read` erlaubt das Inventar; CVE-Informationen werden nur mit
`cves.read` geliefert. Ein gemeinsamer Datenbank-Snapshot verhindert widersprüchliche
Zähler während neuer Reports. Es werden keine Befehle vom Server auf dem Host ausgeführt.

Zusätzlich lassen sich Software-Stücklisten (SBOMs) importieren. Ein Inventar
gehört zu einem Host und einer Anwendung, einem Container-Image oder einer
manuellen Installation. Mehrere Versionen und Vorkommen desselben Pakets bleiben
getrennt. Die SBOM beschreibt den gemeldeten Build oder Installationsstand;
sie beweist nicht, dass genau dieses Image oder Binary gerade läuft.

## SBOM importieren und prüfen

1. **Software → SBOM importieren** öffnen und einen Host auswählen.
2. Einen stabilen Inventarschlüssel vergeben, z. B. `webshop-production`, dazu
   Bezeichnung, Art und optional Image-Digest oder Installationsort.
3. CycloneDX **JSON 1.4–1.7** oder SPDX **JSON 2.2/2.3** hochladen oder einfügen.
   Grenzen: 8 MB einschließlich Import-Metadaten, 5000 Komponenten und höchstens
   100 Inventare je Host. Eine vollständige Schema-Zertifizierung findet nicht statt;
   die für das Inventar benötigten Felder werden validiert. Widersprüchliche
   Versionen, doppelte Komponentenreferenzen und ungültige PURLs werden abgelehnt.
4. Für die Sicherheitsprüfung unter **CVEs → Quellen** eine OSV-Quelle aktivieren.
   **Bei OSV prüfen** übermittelt passende Package URLs einschließlich Version an
   diese Quelle. Der Import selbst löst keine externe Anfrage aus.

Ein erneuter Import mit demselben Host und Schlüssel ersetzt ausschließlich dieses
Inventar. Alte Komponenten und Bewertungen werden entfernt. Ein leeres Inventar
ist zulässig. **Entfernen** löscht das betreffende Inventar; die SBOM kann erneut
importiert werden. Laufende Prüfungen erkennen Neuimporte und übernehmen ihre
Ergebnisse dann nicht mehr in die neue Generation.

Der OSV-Abgleich unterstützt eindeutige, versionierte PURLs für npm, Cargo,
PyPI, Maven, Go, RubyGems, NuGet und Composer. Andere Komponenten bleiben sichtbar
unbekannt. PURLs mit zusätzlichen Qualifiern oder Subpfaden werden nicht extern
abgefragt: insbesondere werden private Repository-Adressen nicht übermittelt und
Pakete daraus nicht automatisch öffentlichen Paketen gleichen Namens zugeordnet.
Container-Systempakete benötigen eine eigene Distributionszuordnung; sie werden
nicht anhand der Distribution des Hosts bewertet.

Es werden die Versionsregeln des jeweiligen OSV-Ökosystems verwendet. Auch
GHSA- und RUSTSEC-Meldungen ohne CVE-ID werden angezeigt; ihre Links führen zum
OSV-Original. **In OSV keine Treffer** ist ein begrenztes Abfrageergebnis und
kein allgemeiner Sicherheitsnachweis. Die Ergebnisse werden 24 Stunden pro Quelle,
Adresse und PURL zwischengespeichert. Veraltete Inventare, abgeschaltete Quellen,
Formatfehler, Seitenlimits und fehlgeschlagene Abfragen ergeben keinen neuen
positiven Sicherheitsstatus. Bekannte offene Meldungen bleiben bei Fehlern erhalten.

Prüfungen laufen nach einem Klick, höchstens zwei gleichzeitig, bis 2000
unterschiedliche Paketversionen, in Batches zu 100, mit vollständiger Pagination
(höchstens fünf Seiten pro Batch) und höchstens 60 Sekunden Gesamtdauer.
Die Quelle wird vor der Ergebnisübernahme erneut auf Änderungen geprüft.
Bei mehreren OSV-Quellen wird die erste aktive, bevorzugt uneingeschränkte Quelle
verwendet; ihre Ökosystem-Einschränkung wird berücksichtigt.

## Automatischer Import aus einer Build-Pipeline

`PUT /api/v1/hosts/{host_id}/inventories/{key}` benötigt `hosts.write` und CSRF.
`GET /api/v1/software/inventories` benötigt `hosts.read` und unterstützt `host_id`.
`DELETE /api/v1/hosts/{host_id}/inventories/{key}` benötigt `hosts.write` und CSRF.
`POST /api/v1/software/inventories/{id}/scan` benötigt `sources.run`, `hosts.read`
und `cves.read` sowie CSRF. Paketlisten und Inventar-Metadaten bleiben auch für
Leser ohne `cves.read` zugänglich; Sicherheitsdetails werden ausgeblendet.

Für CI oder Collector-Werkzeuge gibt es `PUT /api/v1/agent/inventories/{key}` mit
dem vorhandenen Host-Bearer-Token. Der Token bestimmt den Host; eine Host-ID im
Body verleiht keinen Zugriff auf einen anderen Host. Dieser Endpunkt importiert
Inventardaten und führt weder Befehle noch eine Sicherheitsprüfung aus.

Der JSON-Body sieht so aus (`sbom` enthält das vollständige Dokument):

```json
{
  "label": "Webshop",
  "kind": "application",
  "identity": "/opt/webshop",
  "sbom": {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "components": [
      {"bom-ref": "lodash", "type": "library", "name": "lodash",
       "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20"},
      {"bom-ref": "private", "type": "application", "name": "Meine Anwendung",
       "version": "1.0"}
    ]
  }
}
```

Beispiel für einen Linux-CI-Schritt: den Body als `inventory.json` bereitstellen;
der Header wird aus der Standard-Eingabe gelesen, damit der Token nicht in
Prozessargumenten steht. Der Token muss als CI-Geheimnis gesetzt sein.

```sh
printf 'header = "Authorization: Bearer %s"\n' "$PATCHWATCH_TOKEN" |
  curl --fail-with-body --config - --request PUT \
    --header 'Content-Type: application/json' --data-binary @inventory.json \
    'https://patchwatch.example.org/api/v1/agent/inventories/webshop-production'
```

Die Software-Liste kann mit `kind=system|application|container|manual` gefiltert
werden. Die Suche berücksichtigt auch Inventarbezeichnung, PURL und Image-Digest
oder Installationsort. Automatische Host-Scans für nvm/rustup und direkte
Lockfile- oder Docker-Socket-Scanner sind damit noch nicht implementiert: deren
Ergebnisse können über die SBOM-Schnittstelle geliefert werden.
