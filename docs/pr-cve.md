## Was ändert sich?
Basis: `feat/server` (gestapelt; nach dem Merge der vorherigen PRs Basis auf `main` stellen, **Merge-Commit**).

- `CveSource`-Trait mit Adaptern für Ubuntu (inkrementell per Cursor), Debian (`If-Modified-Since`, streamendes
  Parsen) und OSV (optional, je Host-Kernelversion); HTTP mit Timeouts, Größenlimit, Retry/Backoff + Jitter
- Normalisierung und Speicherung je (CVE, Quelle, Release, Paket), Änderungserkennung -> Events -> Neubewertung
  betroffener Hosts -> Statuswechsel -> ntfy; Watchlist-Benachrichtigungen
- Bewertung (`eval.rs`, reine Funktion) für den **laufenden** Kernel inkl. „gefixt installiert, Neustart nötig“;
  **Proxmox immer UNKNOWN** („manuell prüfen“ + Link), kein Alarm; manuelle Prüfung verfällt bei Kernelwechsel
- Fehlerrobustheit: alter Stand bleibt, Fehler sichtbar („veraltet seit …“), Alarm nach 3 Fehlschlägen
- API: `/feeds` (Zustand), `POST /feeds/refresh`, Review-Endpunkte, Matrix mit Live-Fallback und `manual_review`
- Scheduler stündlich (konfigurierbar, Jitter)

## An echten Antworten geprüft (Fixtures in `server/tests/fixtures`)
- Ubuntu: kein „updated since“-Parameter (alle Kandidaten 422) -> Cursor-Logik; 3,7 MB je 20-CVE-Seite
- Debian: kein ETag, nur `Last-Modified`; `TEMP-…`-IDs und `fixed_version: "0"` kommen vor
- OSV: fremde Ökosysteme in `affected[]`, CVE-ID nur in der OSV-ID, Paginierung
- Beim Testen gefundener Fehler: doppelte Einträge je Schlüssel ließen den Import scheitern (jetzt dedupliziert, Regressionstest)

## Geprüft
- fmt, clippy -D warnings, 94 Tests (u. a. Feed-Änderung -> Event -> Host-Status, Ubuntu 22.04/24.04, Debian trixie, Proxmox 9)
- Live gegen die echten Feeds: 32 s Erstimport (Debug-Build), zweiter Abruf 0,27 s (304/Cursor), echter Host bewertet

Closes #<CVE-Modul-Issues>
