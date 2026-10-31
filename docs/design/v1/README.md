# Design v1 (Stand vor der UI-Überarbeitung)

Sicherung der ersten Web-UI: Top-Navigation (Hosts, CVEs, Matrix-Platzhalter, Einstellungen),
Host-/Token-Verwaltung in den Einstellungen.

- **Git-Tag:** `design-v1` (Commit `e82fe5f`, Branch `feat/web`)
- **Design-Vorgaben:** [`DESIGN.md`](DESIGN.md) (Kopie von `web/DESIGN.md` zum Zeitpunkt des Tags)
- **Screenshots:** [`screenshots/`](screenshots) – Login, Hosts, Host-Detail (Ubuntu, Proxmox), CVEs,
  Einstellungen; hell/dunkel, Desktop (1440 px) und mobil (390 px). Lange Seiten sind auf 2200 px gekürzt.
  Dateinamen: `<seite>-<desktop|mobile>-<light|dark>.png`.

## Stand wiederherstellen

```bash
git fetch --tags
git checkout design-v1          # detached HEAD; für Änderungen: git checkout -b fix/ui-v1 design-v1
cd web && npm ci && npm run dev
```

Die UI braucht die API (`PATCHWATCH_API_URL`, Standard `http://127.0.0.1:8080`); Beispieldaten liefert
`scripts/dev-seed.py`.

## Screenshots neu erzeugen

```bash
PW_MODULE=/pfad/zu/node_modules/playwright PW_CHROME=/pfad/zu/chrome PW_PASSWORD=… \
  node scripts/screenshots.mjs docs/design/v1/screenshots
```

Weitere Optionen stehen im Kopf von `scripts/screenshots.mjs`.
