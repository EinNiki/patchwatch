# Nachtlauf 2026-11-12: Phase 6, Agent und Deployment (Dateiprüfung)

Nur Dateiprüfung durch einen Sonnet-Agenten: lesen, shellcheck, systemd-analyze verify auf Kopien, docker compose
config mit Env-Kopie. Kein musl-Build, keine Agent-Tests, kein Containerstart (Speicherregel). Nichts geändert.

# Phase 6: Dateiprüfung Agent-Dateien, Deployment, README (nur Lesen)

Stand: Worktree /home/claude/patchwatch-night, Branch overnight/2026-11-12. Nichts geändert, nichts gebaut, nichts ausgeführt außer `shellcheck`, `systemd-analyze verify` (auf Kopien unter .../scratchpad/night/units), `docker compose --env-file <Kopie> config -q`, `cmp`, `grep`, `stat`.

## Zusammenfassung

| Schwere | Anzahl |
|---|---|
| hoch | 1 |
| mittel | 4 |
| niedrig | 9 |
| Hinweis | 6 |

## Funde

### hoch

**H1. Agent-Installation und Update scheitern absichtlich, solange PW_PUBKEY ein Platzhalter ist**
- Datei: agent/dist/install.sh:97 (identisch install.sh:97); README.md:37-60
- Beleg: `PW_PUBKEY="__MINISIGN_PUBLIC_KEY_NOT_CONFIGURED__"`; `pw_verify_signature` gibt dafür immer Fehler zurück (Zeile 122-124), `install.sh` bricht mit "Prüfung fehlgeschlagen" ab. release.yml:48-51 bricht ohne Secret `MINISIGN_SECRET_KEY` ab. Das ist laut README gewollt, aber bis zur Einrichtung ist kein Release nutzbar.
- Fix: Schlüsselpaar erzeugen, Secret setzen, öffentliche Zeile in agent/dist/install.sh eintragen und nach install.sh kopieren (README-Schritte 1-4).

### mittel

**M1. README nennt drei Umgebungsvariablen, die der Code nicht liest**
- Datei: README.md:223
- Beleg: `PATCHWATCH_CVE_UBUNTU_OVAL_MAX_BYTES`, `..._OVAL_MAX_XML_BYTES`, `..._OVAL_TIMEOUT_SECS`. In server/src/config.rs gibt es nur `s("CVE_UBUNTU_OVAL_URL")` (Zeile 387); die Felder `ubuntu_oval_max_bytes`/`ubuntu_oval_max_xml_bytes` (Zeile 137-138, 179-180) haben feste Standardwerte und werden nicht aus der Umgebung befüllt; `OVAL_TIMEOUT` kommt in config.rs gar nicht vor.
- Fix: Variablen im README streichen (oder im Server einlesen und prüfen).

**M2. Kein Healthcheck für den Proxy; Start-Reihenfolge wartet nicht auf Gesundheit**
- Datei: docker-compose.yml:63-67 (web), 77-80 (proxy)
- Beleg: healthcheck in compose nur für postgres (Zeile 14-18). Server und Web haben HEALTHCHECK im Dockerfile (server/Dockerfile:16, web/Dockerfile:22), der Proxy (caddy:2-alpine) hat keinen. `web` und `proxy` nutzen `depends_on` ohne `condition: service_healthy`.
- Fix: `depends_on` mit `condition: service_healthy` für server/web setzen und für caddy einen Healthcheck (z. B. `caddy validate` oder wget auf Port 80) ergänzen.

**M3. images.yml veröffentlicht bei jedem Push auf `dev` auch den Tag `latest`**
- Datei: .github/workflows/images.yml:7, 39-41
- Beleg: Trigger `branches: [dev, main]`, Tags `latest`, `dev`, `sha-...`; docker-compose.yml:22,64 nutzt standardmäßig `${PATCHWATCH_VERSION:-latest}`. Ein ungetesteter dev-Stand wird damit zur Standardversion.
- Fix: `latest` nur auf main (bzw. nur im Tag-Release) setzen, z. B. `type=raw,value=latest,enable={{is_default_branch}}`.

**M4. README hat keinen Abschnitt "Qualitätsprüfung"**
- Datei: README.md (Überschriften Zeile 1-489, keiner dieses Namens; grep -i "Qualit" in README und docs/*.md ohne Treffer)
- Beleg: Prüfbefehle stehen verstreut: `sh agent/tests/install_test.sh` (Zeile 60) und "Tests:" im Entwicklungsabschnitt (README.md, nach Zeile 470). Shellcheck, cargo fmt/clippy, cargo-deny, npm audit und CodeQL aus ci.yml/security.yml sind nicht beschrieben.
- Fix: Abschnitt "Qualitätsprüfung" mit allen CI-Befehlen (fmt, clippy, test, shellcheck, install_test, npm lint/typecheck/test/build, cargo-deny, npm audit) anlegen.

### niedrig

**N1. `--version` im Installer wird nicht validiert (Update-Skript tut es)**
- Datei: install.sh:33, 81 (agent/dist/install.sh identisch)
- Beleg: `URL_BASE="$BASE/download/$VERSION"` mit beliebigem Text; das Update-Skript prüft dagegen `^v[0-9]+\.[0-9]+\.[0-9]+$` (Zeile 234). Integrität bleibt durch Summe und Signatur geschützt, die URL kann aber umgebogen werden.
- Fix: dieselbe Regex nach dem Argument-Parsing verwenden (außer bei `latest`).

**N2. wget-Rückfall ohne HTTPS-Erzwingung**
- Datei: install.sh:87
- Beleg: `curl ... --proto '=https' --tlsv1.2`, aber `wget -q -O` ohne `--https-only`; `PATCHWATCH_RELEASE_BASE` kann auf http zeigen (Integrität sichern Summe und Signatur, Vertraulichkeit nicht).
- Fix: `wget --https-only -q -O` oder Basis-URL auf `https://` prüfen.

**N3. Härtung der Units ist gut, aber nicht vollständig**
- Datei: agent/dist/patchwatch-agent.service:19-32, patchwatch-agent-checkin.service:19-32 (und die Kopien in install.sh:295-308, 342-355)
- Beleg: vorhanden sind NoNewPrivileges, CapabilityBoundingSet=, ProtectSystem=strict, ProtectHome, PrivateTmp, PrivateDevices, ProtectKernel*, ProtectControlGroups, RestrictAddressFamilies, RestrictNamespaces, LockPersonality, MemoryDenyWriteExecute, SystemCallFilter. Es fehlen u. a. ProtectKernelLogs, ProtectClock, ProtectHostname, ProtectProc, RestrictSUIDSGID, SystemCallArchitectures=native, UMask.
- Fix: diese Optionen ergänzen (vorher auf einem Testhost prüfen, ob der Agent noch läuft).

**N4. CI prüft nur agent/dist/install.sh, nicht die Kopie im Wurzelverzeichnis**
- Datei: .github/workflows/ci.yml:46-49
- Beleg: `shellcheck -s sh -S warning agent/dist/install.sh`; Kopie install.sh und das Testskript fehlen. Die Dateien sind heute identisch (`cmp` ohne Unterschied), aber nichts sichert das ab (README Schritt 3 verlangt manuelles `cp`).
- Fix: `cmp install.sh agent/dist/install.sh` und `shellcheck agent/tests/install_test.sh` in den CI-Schritt aufnehmen.

**N5. shellcheck-Funde in agent/tests/install_test.sh (alle unkritisch)**
- Datei: agent/tests/install_test.sh:90 (SC2034 Warnung, falsch positiv: `PW_PUBKEY` wird von der eingebundenen Bibliothek gelesen); Zeilen 142-210 viele SC2015 (A && B || C), 178 SC2181, 187/203/205/207 SC2016 (Info).
- Fix: Zeile 90 mit `# shellcheck disable=SC2034` markieren; SC2015 bei Bedarf durch if/else ersetzen.

**N6. Root-install.sh ist nicht ausführbar, agent/dist/install.sh schon**
- Datei: install.sh (Git-Modus 100644), agent/dist/install.sh (100755)
- Beleg: `git ls-files -s`; Inhalt identisch (gleicher Blob 05e4b4d9). README ruft `sh install.sh` auf, daher ohne Folge.
- Fix: Modus angleichen (`chmod +x` und committen) oder bewusst belassen.

**N7. .dockerignore deckt nur das Wurzel-`.env` ab**
- Datei: .dockerignore (7 Zeilen: target, .git, web/node_modules, web/.next, .env, docs; Zeilen 1-6 laut Ausgabe)
- Beleg: `web/Dockerfile:11` kopiert `web/` komplett; ein lokales `web/.env.local` oder `web/.env` würde in den Build-Kontext (und in die Build-Stufe) gelangen. Es gibt kein web/.dockerignore und kein server/.dockerignore. `.github`, `scripts`, `.claude` werden ebenfalls mitgesendet.
- Fix: `**/.env*`, `.github`, `.claude`, `scripts` in .dockerignore aufnehmen.

**N8. README Zeile 96: "Web-UI folgt; bis dahin per API" ist veraltet**
- Datei: README.md:96-98
- Beleg: Die Web-UI besitzt laut README selbst die Seite "Agents" mit "Agent hinzufügen" (Zeile ~410) und `web/src/app/(app)/agents/page.tsx` existiert.
- Fix: Satz auf die UI verweisen lassen, API-Beispiel als Alternative kennzeichnen.

**N9. Release-Workflow ohne CI-Voraussetzung**
- Datei: .github/workflows/release.yml:3-5, 11-81
- Beleg: Tag `v*` löst Build und Veröffentlichung aus; kein `needs` auf ci.yml, keine Tests im Release-Job.
- Fix: Tests im Release-Job ausführen oder Tag-Schutz/Branch-Prüfung festlegen.

### Hinweis

- **Hi1.** Update-Skript existiert nicht als Datei in agent/dist/, `patchwatch-agent-update` wird von install.sh:208-255 per Heredoc erzeugt (README beschreibt es korrekt). Das erzeugte Skript wurde extrahiert und mit shellcheck geprüft: nur SC1091 (Info).
- **Hi2.** release.yml:39-40 veröffentlicht install.sh nur mit `.sha256`, ohne `.minisig`; wer `install.sh` herunterlädt, verlässt sich auf TLS/GitHub.
- **Hi3.** Basis-Images nur per Tag, nicht per Digest: postgres:17-alpine (compose:6), caddy:2-alpine (compose:78), node:22-slim (web/Dockerfile:2,7,14), debian:trixie-slim (server/Dockerfile:10), rust:1.95-slim-trixie (server/Dockerfile:2; passt zu rust-toolchain.toml 1.95.0).
- **Hi4.** postgres hat kein `cap_drop`/`read_only` (compose:5-19), server/web/proxy schon (compose:59-61, 70-73, 91-93); bei Postgres bewusst, da es schreibt.
- **Hi5.** Caddyfile setzt nur HSTS und `-Server` (deploy/Caddyfile:30-33); Sicherheits-Header kommen für die UI aus web/next.config.ts (nosniff, X-Frame-Options, Referrer-Policy, Permissions-Policy), für die Server-API wurden sie hier nicht geprüft.
- **Hi6.** `PATCHWATCH_DATABASE_URL` wird in compose:28 aus `POSTGRES_PASSWORD` zusammengesetzt; Sonderzeichen im Passwort würden die URL brechen (.env.example:2 empfiehlt `openssl rand -hex 24`). Bei einem bestehenden Token (`KEEP_TOKEN=yes`) korrigiert install.sh die Rechte von /etc/patchwatch/token nicht (install.sh:260-264).

## Geprüft und in Ordnung

**Agent-Dateien**
- agent/dist enthält: install.sh, patchwatch-agent.service/.timer, patchwatch-agent-checkin.service/.timer, agent.toml.example. In dist/ steht kein Update-Skript (siehe Hi1).
- `cmp install.sh agent/dist/install.sh`: identisch.
- Units in install.sh (Heredocs) sind zeilengleich zu den Dateien in agent/dist (4 von 4 per diff).
- `systemd-analyze verify` auf den vier Kopien: keine Meldung zu patchwatch-Units (nur Fremdwarnungen zu xfs_scrub vom Host, kein Bezug).
- Timer wie in README: patchwatch-agent.timer `OnCalendar=*-*-* 12:00:00`, `RandomizedDelaySec=30min`, `Persistent=true`; Check-in-Timer `OnCalendar=minutely` (`RandomizedDelaySec=15`, `AccuracySec=1s`).
- Services: `User=patchwatch`, `Group=patchwatch`, `Type=oneshot`, `LoadCredential=token:/etc/patchwatch/token`, `StateDirectory` mit 0700, Härtung siehe N3.
- Token-Datei: `umask 077`, `chown root:root`, `chmod 0600` (install.sh:261-263); Token nie im Befehl (Abfrage ohne Echo, `--token-file`, `PATCHWATCH_TOKEN`).
- Prüfsumme (Codeprüfung, nicht ausgeführt): `pw_expected_hash` (install.sh:104-110) nimmt nur Zeilen, deren Dateiname exakt dem Namen entspricht (`*name` erlaubt, `./name`, `xname` nicht); kein Eintrag, mehrere verschiedene Hashes oder kein 64-stelliger Hex-Wert lassen die Funktion scheitern; Vergleich mit selbst berechnetem sha256 (Zeile 116-117); Abbruch über `die` in Zeile 180, vor jeder Installation. Signaturprüfung zusätzlich verpflichtend, fehlendes minisign/Schlüssel/Datei bedeutet Fehler. install_test.sh deckt fremden Namen und falschen Hash ab (Zeile 43-65).
- Update mit Sicherung `.prev`, Probelauf der neuen Datei, Rückfall (install.sh:135-146); Hauptversion eingehalten (Zeile 153, 235).
- shellcheck: install.sh und agent/dist/install.sh nur SC1091 (Info, wegen eingebundener Datei); eingebettete Bibliothek: sauber; erzeugtes Update-Skript: nur SC1091. Weitere Shell-Skripte im Repo: nur agent/tests/install_test.sh (siehe N5). Es gibt keine scripts/*.sh (nur .mjs und dev-seed.py).
- Dateirechte: agent/dist/install.sh und scripts/dev-seed.py ausführbar (775), restliche Dateien 664; `.env.example` 664.

**Deployment**
- `docker compose --env-file <Kopie von .env.example + POSTGRES_PASSWORD> config -q`: Exit 0 (nur geparst).
- Ports: server 127.0.0.1:8080, web 127.0.0.1:3000, Postgres ohne veröffentlichten Port, Proxy `${PATCHWATCH_BIND:-0.0.0.0}:80/443` (so im README und in .env.example dokumentiert).
- restart: `unless-stopped` bei allen vier Diensten. Volumes: pgdata, caddy_data, Caddyfile read-only. Geheimnisse nur über `${...}`-Env, keine Werte im Compose (POSTGRES_PASSWORD mit `:?`-Pflichtprüfung).
- Härtung: `no-new-privileges` überall, `cap_drop: [ALL]` (Proxy nur NET_BIND_SERVICE), `read_only` für server/web mit tmpfs für web.
- server/Dockerfile und web/Dockerfile: Mehrstufig, Laufzeit mit `USER 10001` (Nicht-root), feste Tags (rust:1.95, node:22, debian:trixie), `--locked`/`npm ci`, HEALTHCHECK vorhanden (Server-Unterbefehl `healthcheck` fragt /readyz, existiert in server/src/main.rs:13-25 und routes/health.rs).
- .env.example: alle in compose benutzten Variablen sind dokumentiert (POSTGRES_PASSWORD, PATCHWATCH_VERSION, DOMAIN, HTTP_PORT, HTTPS_PORT, BIND, TIMEZONE, DAILY_SUMMARY_TIME, CVE_*, NTFY_*, SECRET_KEY, NOTIFY_ALLOWED_HOSTS, ALLOWED_ORIGINS, ADMIN_PASSWORD, OIDC_*); keine echten Werte (nur Platzhalter, `POSTGRES_PASSWORD=` leer). `PATCHWATCH_TRUST_PROXY` ist in compose fest gesetzt und nicht in .env.example, das ist stimmig.
- deploy/Caddyfile: `encode zstd gzip`, `handle /api/*` an server:8080, Rest an web:3000, HSTS, `-Server`; WebSocket-Upgrade wird von `reverse_proxy` selbst durchgereicht (README Zeile 212 sagt dasselbe).
- Workflows: alle Actions auf Commit-SHA festgelegt, `permissions: contents: read` als Standard, `persist-credentials: false`; Geheimnisse nur als `secrets.GITHUB_TOKEN` und `secrets.MINISIGN_SECRET_KEY` (Letzteres nur über `env`, Ausgabe von minisign nach /dev/null, Schlüsseldatei 0600 mit trap). Keine `echo` von Geheimnissen. Im Repo sind keine .env/.pem/.key-Dateien versioniert (server/tests/channel_secrets.rs ist ein Testname).

**README gegen Stand**
- Vorhanden: deploy/Caddyfile, agent/dist/agent.toml.example, agent/tests/install_test.sh, docs/github-setup.md, docs/perf.md, docs/ubuntu-source.md, web/DESIGN.md, scripts/dev-seed.py, server/migrations (bis 0020).
- cargo-Pakete: `-p patchwatch-server` (server/Cargo.toml:2) und patchwatch-agent stimmen.
- npm-Skripte: dev, build, start:prod, lint, typecheck, test existieren in web/package.json.
- Unterbefehle: `create-admin`, `migrate`, `healthcheck`, `serve` (server/src/main.rs:64-87); Agent `checkin`, `status`, `set-token` mit `--stdin`, `--token-file`, `--migrate`, `--no-test`, `--token` (wird abgelehnt), `--dry-run`, `--version` (agent/src/main.rs, agent/src/setcmd.rs). Check-in-Grenzen 60-86400 und `checkin_wait_secs` 0-55 passen zum README.
- PATCHWATCH_*-Variablen im README: alle bis auf M1 im Code oder in compose zu finden (COOKIE_SECURE, CVE_UBUNTU_PAGE_TIMEOUT_SECS, CVE_STALL_TIMEOUT_SECS, UBUNTU_MODE, BULK_RELEASES, PAGE_PAUSE_MS, CONFIG über Präfix-Funktion `s("...")` in config.rs; BIND nur in compose; LIVE_PORT als `NEXT_PUBLIC_PATCHWATCH_LIVE_PORT` in web/src/lib/live.tsx; API_URL in web/next.config.ts; TOKEN in install.sh und Agent).

## Nicht geprüft (braucht Ausführung)

- Ob der Agent unter ProtectSystem=strict, SystemCallFilter=@system-service und MemoryDenyWriteExecute wirklich läuft (apt-Simulation, Lesezugriffe).
- Ob `systemd-analyze security` einen bestimmten Wert ergibt; ob `User=patchwatch` und das Binary vorhanden sind (verify zeigte nichts an, es ist aber nur ein Parsetest).
- Tatsächlicher Lauf von install.sh (root, Netz, minisign), agent/tests/install_test.sh, Prüfsummenabbruch im Echtbetrieb.
- `docker compose up`, Healthcheck-Ergebnisse, Caddy-Syntax per `caddy validate`, Image-Builds, Nicht-root-Betrieb im laufenden Container, Schreibrechte bei `read_only: true` (z. B. ob der Server kein /tmp braucht).
- Funktion der README-Befehle (curl-API-Beispiele, `docker compose exec ... create-admin`), npm-Skripte, cargo-Build; Standardwert von `checkin_wait_secs` im Agent bei fehlendem Eintrag in der von install.sh geschriebenen agent.toml.
- GitHub-Actions-Läufe und Secrets im Repository (ob `MINISIGN_SECRET_KEY` gesetzt ist).
