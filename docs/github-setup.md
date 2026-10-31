# GitHub-Setup (ohne gh im Build-Environment)

Die Branches werden per `git push` bereitgestellt. Milestones, Issues, PRs und
Branch-Schutz legst du mit der `gh`-CLI an (nach `gh auth login`).
Auf `main` wird nie direkt gepusht.

## 1. Milestones

```bash
R=EinNiki/patchwatch
for m in "Agent" "Server" "CVE-Modul" "Web" "UI v2" "Matrix-UI (später)"; do
  gh api repos/$R/milestones -f title="$m" >/dev/null && echo "angelegt: $m"
done
```

## 2. Issues (je Milestone)

```bash
R=EinNiki/patchwatch
mk() { gh issue create -R $R --milestone "$1" --title "$2" --body "$3"; }

# Agent
mk Agent "feat(agent): Config und Report-Struktur" "agent.toml, schema_version, serde-Report"
mk Agent "feat(agent): Kernel-Erkennung per dpkg -S" "Laufender Kernel, Paket, neuester installierter Kernel, Fallback linux-image-"
mk Agent "feat(agent): Updates, Security-Updates, reboot-required, Uptime, Proxmox" "apt-get -s, /var/run/reboot-required, pveversion"
mk Agent "feat(agent): optionale Paketliste" "Standard aus; inkl. Quellpaket"
mk Agent "feat(agent): HTTPS-Versand mit Bearer-Token und Exit-Codes" "ureq + rustls, Meldung in journald"
mk Agent "feat(agent): systemd service/timer und install.sh" "User patchwatch, LoadCredential, SHA256-Prüfung"

# Server
mk Server "feat(server): Schema und Migrationen" "hosts, host_packages, cves, cve_source_status, host_cve_status, Queue, Sessions"
mk Server "feat(server): POST /api/v1/report mit Token-Hash" "Validierung, Größenlimit"
mk Server "feat(server): GET-Endpunkte Hosts, Verlauf, CVEs, Matrix" ""
mk Server "feat(server): Admin-Login, CSRF, Rate-Limiting" "argon2, Session-Cookie"
mk Server "feat(server): Stale-Erkennung und ntfy-Benachrichtigung" "26 h, Statuswechsel, Tageszusammenfassung"
mk Server "feat(server): Cleanup-Job Report-Historie (180 Tage)" ""
mk Server "feat(server): Dockerfile und docker-compose" "Healthchecks"

# CVE-Modul
mk CVE-Modul "feat(cve): debversion-Crate (dpkg-Vergleich)" "bereits in chore/bootstrap"
mk CVE-Modul "feat(cve): CveSource-Trait und Scheduler" "60 min mit Jitter, Backoff, Timeouts, Größenlimits"
mk CVE-Modul "feat(cve): Ubuntu-Adapter (inkrementell)" "Fixture aus echter Antwort"
mk CVE-Modul "feat(cve): Debian-Adapter (ETag/If-Modified-Since)" ""
mk CVE-Modul "feat(cve): OSV-Adapter (optional)" ""
mk CVE-Modul "feat(cve): Bewertung inkl. Proxmox-UNKNOWN und Neustart-Status" "Laufender Kernel; kein ntfy bei Proxmox-UNKNOWN"
mk CVE-Modul "feat(cve): Änderungserkennung, Events, Watchlist" ""
mk CVE-Modul "test(cve): Fixtures Ubuntu 22.04/24.04, Debian trixie, Proxmox 9" "inkl. Feed-Änderung -> Event -> Host-Status"

# Web
mk Web "docs(web): DESIGN.md" "Palette, Schriften, Abstände, Statusdarstellung"
mk Web "feat(web): Host-Übersicht" "sortier- und filterbar"
mk Web "feat(web): Host-Detail" ""
mk Web "feat(web): CVE-Liste, Watchlist, Feed-Zustand" "Proxmox: manuell prüfen mit Haken"
mk Web "feat(web): Einstellungen und Login" ""
mk Web "feat(web): Hell/Dunkel, Mobil, Barrierefreiheit" ""

# UI v2
mk "UI v2" "feat(web): Seitenleiste und Agents-Seite" "Navigation Hosts, CVEs, Agents, Benachrichtigungen, Einstellungen; Host- und Token-Verwaltung auf der Agents-Seite"
mk "UI v2" "feat: Agent-Check-in und Report auf Abruf" "Zweiter Timer, Server antwortet nur mit report_requested, Rate-Limit je Host"
mk "UI v2" "feat: Benachrichtigungskanäle in der UI" "ntfy, Matrix, Gotify, Discord, Browser; Geheimnisse verschlüsselt und write-only; SSRF-Schutz"
mk "UI v2" "feat: Live-Updates per WebSocket" "Nur mit Session und passender Origin, Ereignisse per LISTEN/NOTIFY"
mk "UI v2" "feat: Distributionen je CVE und Filter" "Chips je Quelle/Release, Filter Debian gefixt/Ubuntu offen, CVE-Detailseite"

# Matrix-UI
mk "Matrix-UI (später)" "feat(web): Matrix-Ansicht" "Zeilen Hosts, Spalten CVEs, Klick = Begründung und Quellen"
```

## 3. Pull Requests (gestapelt)

Reihenfolge und Basis-Branches:

| Branch | Basis | Schließt |
|---|---|---|
| `chore/bootstrap` | `main` | – |
| `feat/agent` | `chore/bootstrap` | Agent-Issues |
| `feat/server` | `feat/agent` | Server-Issues |
| `feat/cve` | `feat/server` | CVE-Issues |
| `feat/web` | `feat/cve` | Web-Issues |
| `feat/ui-v2` | `feat/web` | UI-v2-Issues (Text: `docs/pr-ui-v2.md`) |

```bash
gh pr create -R EinNiki/patchwatch --base main --head chore/bootstrap \
  --title "chore: Workspace, CI, Security, Release" --body-file docs/pr-bootstrap.md
# danach je Schritt: --base <vorheriger Branch> --head <Branch>; Issue-Nummern per "Closes #N"
```

**Merge mit Merge-Commit, nicht Squash** (gestapelte PRs, sonst Konflikte
in den Folge-Branches): `gh pr merge <nr> --merge`. Nach dem Merge den
Basis-Branch des nächsten PRs auf `main` umstellen
(`gh pr edit <nr> --base main`). Merge erst, wenn alle Checks grün sind.

## 4. Branch-Schutz für main (erst nach dem ersten CI-Lauf)

Required Checks müssen mindestens einmal gelaufen sein, damit GitHub die Namen
kennt. Ablauf: `chore/bootstrap` pushen, PR öffnen, CI abwarten, dann Schutz setzen.

```bash
# Namen der gelaufenen Checks prüfen
gh pr checks <nr> -R EinNiki/patchwatch

gh api -X PUT repos/EinNiki/patchwatch/branches/main/protection --input - <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "contexts": ["rust (fmt, clippy, test)", "web (lint, typecheck, build)",
                 "cargo-deny (advisories, licenses, bans)"]
  },
  "enforce_admins": false,
  "required_pull_request_reviews": {"required_approving_review_count": 0},
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
JSON
```

Passen die `contexts` nicht zu den beobachteten Namen, die Namen aus
`gh pr checks` übernehmen. Bei HTTP 403 (privates Repo ohne Pro/Team): in der
Weboberfläche unter *Settings → Branches → Add rule* für `main`
„Require a pull request before merging“ und „Require status checks to pass“
aktivieren und dieselben Checks auswählen.
