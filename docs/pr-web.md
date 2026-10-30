## Was ändert sich?
Basis: `feat/cve` (gestapelt; nach dem Merge der vorherigen PRs Basis auf `main` stellen, **Merge-Commit**).

- `web/DESIGN.md` vorab (Palette mit gemessenen Kontrasten, Schriften, Abstände, Statusdarstellung), UI hält sich daran
- Next.js 16 (App Router, TS strict, Tailwind 4): Host-Übersicht, Host-Detail, CVE-Liste mit Watchlist und Feed-Zustand,
  Einstellungen (Token-Verwaltung), Login; Navigationsplatz für die Matrix („bald“)
- Nur Rust-API, kein eigenes Backend; Hell/Dunkel, mobil nutzbar (gestapelte Tabellen), Tastatur, Fokus, `aria-sort`
- Status nie nur über Farbe (eigene Icon-Form + Text); fehlende Datenlage (Proxmox, Feed veraltet) nie „grün“
- Server: `GET /hosts/{id}/cves` sortiert vor dem Limit nach Dringlichkeit (Regressionstest)
- Dockerfile (non-root, read-only, Healthcheck), Compose-Dienst `web`, optionaler Caddy-TLS-Proxy, `install.sh` im Release
- `scripts/dev-seed.py` für Beispieldaten

## Beim Prüfen im Browser gefunden und behoben
- Login-Formular konnte vor der Hydration nativ per GET abgeschickt werden (Zugangsdaten in der URL): jetzt `method="post"`
  und Button erst nach Hydration aktiv
- `GET /hosts/{id}/cves` schnitt bei 2000 Zeilen nach CVE-ID statt nach Dringlichkeit ab
- Globale Link-Stile lagen außerhalb der Tailwind-Layer und überschrieben Utility-Klassen; Links im Fließtext waren nur farblich erkennbar
- Gestapelte Mobil-Tabelle verteilte mehrteilige Zellen auf die Label-Spalte

## Geprüft
- fmt, clippy -D warnings, 95 Rust-Tests; Web: lint, typecheck, build
- Playwright gegen echten Server mit Live-Feeddaten: Hell, Dunkel, Mobil; axe-core (WCAG 2.1 AA): 0 Verstöße
- Docker-Images (server, web) gebaut und gehärtet gestartet, Healthchecks `healthy`

Closes #<Web-Issues>
