## Was ändert sich?
Basis: `feat/agent` (gestapelt; nach dem Merge des Agent-PRs Basis auf `main` stellen, **Merge-Commit** verwenden).

- Crate `patchwatch-server` (axum 0.8, sqlx 0.8/Postgres), Migration mit dem kompletten Datenmodell
  (hosts, host_packages, reports, cves, cve_source_status, host_cve_status, watchlist, manual_reviews,
  feed_state, events, jobs, admin_users, sessions)
- `POST /api/v1/report` (Bearer-Token, nur Hash gespeichert, Validierung, 4-MB-Limit)
- GET: Hosts, Detail, Verlauf, Host-CVEs, CVEs, Watchlist, Matrix (fehlende Bewertung = `unknown`), Feeds;
  Host anlegen/Token rotieren/löschen; `/healthz`, `/readyz`
- Admin-Login (argon2id, Session-Cookie, CSRF), Rate-Limits, Config ohne Secrets im Debug/Log
- Stale-Erkennung (26 h), Statuswechsel -> Event -> ntfy-Job (Retry/Backoff), Tageszusammenfassung,
  Cleanup-Job (Report-Historie 180 Tage)
- Job-Queue/Events in Postgres (SKIP LOCKED, LISTEN/NOTIFY), kein Redis (Begründung im README)
- Dockerfile (non-root, Healthcheck), docker-compose (Postgres mit Healthcheck, Port nur auf localhost)

## Geprüft
- fmt, clippy -D warnings, 54 Tests (inkl. 11 Integrationstests gegen Postgres)
- E2E: Server + echtes Agent-Binary, Token/Passwort nicht im Server-Log
- Docker-Image gebaut und gehärtet gestartet (read-only, cap_drop ALL, UID 10001), Healthcheck `healthy`

Closes #<Server-Issues>
