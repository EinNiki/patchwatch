# patchwatch

[![CI](https://github.com/EinNiki/patchwatch/actions/workflows/ci.yml/badge.svg)](https://github.com/EinNiki/patchwatch/actions/workflows/ci.yml)
[![Release](https://github.com/EinNiki/patchwatch/actions/workflows/release.yml/badge.svg)](https://github.com/EinNiki/patchwatch/actions/workflows/release.yml)

Leichtgewichtiges Monitoring für Kernel- und Patch-Stand mehrerer Linux-Server
(Ubuntu, Debian, Proxmox) mit CVE-Abgleich und Web-UI.

Status: im Aufbau. Aufbau: `agent/`, `server/`, `web/`, gemeinsame Crates in `crates/`.
Einrichtung des GitHub-Repos: [docs/github-setup.md](docs/github-setup.md).

## Agent

Statisches musl-Binary (~2 MB), läuft einmal pro Aufruf (systemd-Timer, täglich 12:00
mit `RandomizedDelaySec=30min`), ohne Root-Rechte und ohne offenen Port. Sendet per
HTTPS POST an `/api/v1/report` mit Bearer-Token.

Installation (als root, Token kommt aus dem Server, siehe Betrieb):

```sh
PATCHWATCH_TOKEN=… sh install.sh --server-url https://patchwatch.example.org
```

`install.sh` lädt das Binary aus dem GitHub Release und prüft die SHA256-Summe vor der
Installation. Der Token liegt in `/etc/patchwatch/token` (`root:root 0600`) und wird per
systemd-`LoadCredential` an den Dienst `patchwatch` (kein `DynamicUser`) gereicht.
Konfiguration: `/etc/patchwatch/agent.toml`, Beispiel in `agent/dist/agent.toml.example`.

Exit-Codes: `1` Konfiguration, `2` Erfassung, `3` Server nicht erreichbar, `4` Server lehnt ab.
Fehlermeldungen (ohne Token) landen im journald: `journalctl -u patchwatch-agent`.
`patchwatch-agent --dry-run` gibt den Report als JSON aus, ohne zu senden.
