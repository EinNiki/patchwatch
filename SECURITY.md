# Sicherheitshinweise

## Schwachstellen melden

Bitte keine öffentlichen Issues für Sicherheitslücken. Nutze auf GitHub
„Security → Report a vulnerability“ (Private Vulnerability Reporting) im
Repository `EinNiki/patchwatch`.

## Unterstützte Versionen

Nur die jeweils neueste Release-Version erhält Sicherheitsupdates.

## Betrieb

- Server und Web nur über VPN/WireGuard oder hinter einem TLS-Reverse-Proxy erreichbar machen.
- Agent-Tokens sind pro Host; der Server speichert nur den Hash. Bei Verdacht Token rotieren.
- Keine Tokens, Passwörter oder Cookies in Issues, Logs oder Fixtures posten.
