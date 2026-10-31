# UI v2

Design: [`web/DESIGN.md`](../../../web/DESIGN.md) (v2). Referenz und Prüfbericht zum Skill `hig`: [`skills-review.md`](skills-review.md).
UI v1 bleibt über den Tag `design-v1` und [`../v1/`](../v1/README.md) reproduzierbar.

## Screenshots neu erzeugen

```sh
# Stack läuft (Server :8080, Web :3100, Beispieldaten aus scripts/dev-seed.py)
PW_MODULE=/pfad/zu/node_modules/playwright PW_CHROME=/pfad/zu/chrome PW_PASSWORD=… \
  PW_MAX_HEIGHT=1500 node scripts/screenshots.mjs docs/design/v2/screenshots
PW_MODULE=… PW_CHROME=… AXE_JS=…/axe.min.js PW_PASSWORD=… node scripts/a11y.mjs   # axe-core, Exit 1 bei Verstößen
```

Dateinamen: `<seite>-<desktop|mobile>-<light|dark>.png`. Seiten: `hosts`, `host-ubuntu`, `host-proxmox`, `cves`,
`cves-filtered` (Debian gefixt, Ubuntu offen), `cve-detail`, `agents`, `agents-waiting` („wartet auf Agent …“),
`agents-add`, `agents-token` (Token einmalig, Agent danach gelöscht), `notifications`, `notification-ntfy|matrix|browser`,
`settings`, `menu` (nur mobil), `login`.

Zustände ohne Foto sind per axe geprüft: Dialoge (Agent hinzufügen, Löschen bestätigen) und das mobile Menü.
Das Test-Token auf `agents-token-*` gehörte zu einem sofort wieder gelöschten Demo-Agent.
