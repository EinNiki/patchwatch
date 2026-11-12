# Nachtlauf 2026-11-12: Zustand

Nur der Dirigent schreibt diese Datei. Zeiten in UTC (Berlin = UTC+1).

## Vorbedingung: Warten auf UI-Sitzung (claude-squishy-rabbit)
- Warten begonnen: 2026-11-11 21:51 UTC. Fertig gemeldet: 23:59 UTC (status idle, bucket completed, alles auf origin/dev 8cf3064).
- Session-Werkzeuge vorhanden (list_events braucht limit 100, weil der Filter nach dem Lesen greift).

| Check (UTC) | Ergebnis | Notiz |
|---|---|---|
| 21:51 | NICHT FERTIG | working; Spaltenbreiten der Hostliste |
| 22:53 | NICHT FERTIG | working; E2E-Test Agents-Seite |
| 23:59 | FERTIG | idle/completed; alles gepusht, Prüfungen grün |

Entscheidungen beim Warten:
- Die zuerst angelegte STATE.md wurde um 22:04 UTC von der UI-Sitzung per `git stash -u` in
  stash@{0} ("wip-aufgabe-b-hostliste") mitgenommen. Sie wurde im Repo nicht neu angelegt (ein
  `stash pop` der UI-Sitzung wäre sonst gescheitert); der Wartezustand lag solange außerhalb des Repos.
- Nach Abschluss: Arbeitsbaum sauber, `git log origin/dev..HEAD` leer, also keine "Reste der
  UI-Sitzung" zu committen. stash@{0} und stash@{1} bleiben unangetastet (stash@{0} ist ein alter
  Zwischenstand von Aufgabe B: README.md, web/src/app/(app)/page.tsx, scripts/e2e-hostlist-cve.mjs;
  die Aufgabe ist inzwischen committet).

## Nachtlauf
- Start: 2026-11-12 00:00 UTC (01:00 Berlin). 7-Stunden-Grenze: 07:00 UTC. Keine neue Phase nach
  05:30 UTC (06:30 Berlin). Bericht spätestens 07:00 UTC.
- Branch: overnight/2026-11-12 (Push per Dry-Run erlaubt). Basis: dev 8cf3064.
- Auffällig: Im Repo gibt es keine CLAUDE.md (der Auftrag nennt sie als Lektüre).

| Phase | Status | Start | Ende | Gefunden | Behoben | Offen |
|---|---|---|---|---|---|---|
| 0 Sicherung und Branch | fertig | 00:00 | 00:01 | - | - | - |
| Umgebung, Modelltest | fertig | 00:01 | 00:25 | - | - | - |
| 1 UI-Restarbeiten | offen | | | | | |
| 2 Qualitätsschranken | offen | | | | | |
| 3 Responsiv | offen | | | | | |
| 4 Funktionstests | offen | | | | | |
| 5 Daten, Zeit, Robustheit | offen | | | | | |
| 6 Agent und Deployment | offen | | | | | |
| 7 Sicherheit | offen | | | | | |
| 8 Aufräumen und Push | offen | | | | | |
| 9 Bericht | offen | | | | | |

Phase 0: Tag before-overnight-2026-11-12 auf 8cf3064 angelegt und gepusht. Tag
design-v2-2026-11-11 existiert bereits lokal und auf origin (von der UI-Sitzung).

## Umgebung (Stand 00:25 UTC)
- Eigener Server "claude" (kein frischer Cloud-Klon), 4 CPU, 5,3 GB RAM, 2 GB Swap, 21 GB Platte frei. Auf der
  Maschine laufen fremde Dienste (lagerplatz-web/-api, Redis).
- Vorhanden: docker 29.9, node 22, npm 9, cargo/rustc 1.95 (musl-Target), shellcheck, systemd-analyze, Playwright
  und Chromium (~/.npm/_npx/..., ~/.cache/ms-playwright). Kein psql/postgres im PATH. Netz: npm ok, index.crates.io ok.
- Modelltest: sonnet, opus, haiku antworten, Modellparameter funktioniert.
- Reste der UI-Sitzung laufen weiter: zwei Stacks (Server 8080 + Web 3100/4100 + pw-ui-pg; Server 8081 + Web
  3200/4200 + pw-snap-pg). Die beiden Debug-Server belegen zusammen ca. 2 GB RAM und ca. 600 MB Swap.
- Entscheidung 1: Das Beenden der verwaisten Prozesse des Snapshot-Stacks wurde von der Rechteprüfung der Umgebung
  abgelehnt ("Interfere With Workloads"). Es wird nichts beendet oder gestoppt.
- Entscheidung 2: Gearbeitet wird in einem eigenen Worktree /home/claude/patchwatch-night (Branch
  overnight/2026-11-12). /home/claude/patchwatch steht wieder sauber auf dev. Grund: Die laufende Instanz auf Port
  3100 liest aus web/.next des Hauptverzeichnisses; ein Build dort hätte sie zerstört.
- Entscheidung 3 (Speicherregel): Swap steht bei 58 % (Schwelle 50 %), verfügbar 2,0 GB, keine Swap-Aktivität. Der
  Swap ist durch die ruhenden Prozesse der UI-Sitzung belegt; Warten ändert nichts, eigene Container gibt es nicht.
  Nach der Regel werden schwere Schritte (Build, Browser, Docker, Tests) deshalb ÜBERSPRUNGEN, solange die Prüfung
  nicht besteht. Vor jeder Phase wird neu geprüft. Bis dahin laufen nur lesende Prüfungen und leichte Werkzeuge
  (fmt, lint, typecheck, shellcheck).
- Auslegung Parallelität: höchstens 2 rein lesende Agenten gleichzeitig; sie schreiben ihre Befunde außerhalb des
  Arbeitsbaums, der Dirigent übernimmt sie nach docs/overnight/.

## Agenten
| Nr | Modell | Auftrag | Ergebnis |
|---|---|---|---|
| 1-3 | haiku | Wartebedingung prüfen (3 Checks) | 2x nicht fertig, 1x fertig |
| 4 | sonnet | Modelltest | ok |
| 5 | opus | Modelltest | ok |
| 6 | haiku | Umgebungsprüfung, Modelltest | ok, Ergebnis oben |

## Offene Punkte
