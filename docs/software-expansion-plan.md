# Plan: zusätzliche Software-Inventare

1. Pro Host mehrere benannte Inventare speichern. Eine Komponente wird je Vorkommen
   erhalten; weder andere Versionen noch andere Container werden zusammengefasst.
2. CycloneDX- und SPDX-JSON importieren, über Benutzeroberfläche und Host-Token-API.
   Neuimporte ersetzen nur das benannte Inventar, validiert und atomar.
3. Eindeutige Ökosystem-PURLs bei OSV abfragen. Ergebnis-IDs, Aktualität und
   Herkunft speichern; unvollständige oder fehlende Bewertungen bleiben unbekannt.
4. Bestehende Software-Liste erweitern: Art, Herkunft, Version, Fundort und
   getrennte Vorkommen anzeigen. Import, Ersetzen, Entfernen und Prüfen bedienbar machen.
5. Parser, Berechtigungen, Token-Bindung, Cache, Pagination, Fehler und parallele
   Neuimporte testen; Oberfläche bauen und im Browser prüfen.

Abgrenzung: Inventare sind gemeldete Snapshots. Automatische Laufzeiterkennung,
eigene Container-/Lockfile-Scanner und die Einbeziehung aller Paketfunde in den
Host-Gesamtstatus sind weitere Ausbaustufen. Der SBOM-Endpunkt dient ihnen als
gemeinsamer Eingang. Details und Grenzen stehen in [software-inventory.md](software-inventory.md).

## Umsetzung und Prüfung (17. November 2026)

Die fünf Schritte sind implementiert. Erfolgreich: 387 Servertests, 121 Webtests,
Clippy mit `-D warnings`, Typecheck, ESLint und Produktionsbuild. Im Browser wurden
der JSON-Import, getrennte Versionen, Containerfilter, echte OSV-Ergebnisse und
der mobile Importdialog geprüft. Die automatisierte Dateiauswahl blieb im
Browserwerkzeug hängen; dieser Bedienweg ist nicht als im Browser geprüft bestätigt.

Offener bestehender Befund: `npm audit --omit=dev` meldet für Next.js 16.4.3 eine
moderate Schwachstelle (GHSA-mfr8-8qww-v76h); als Update wird 16.4.6 angeboten.
Die Abhängigkeit wurde im Rahmen dieser Erweiterung nicht geändert.
