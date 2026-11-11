# Debian-Quelle: Übertragungsmenge und bedingte Anfrage

Stand: 2026-11-11 (nur lesend: HEAD-Anfragen an `https://security-tracker.debian.org/tracker/data/json`, kein Download).

## Warum die Übertragungsmenge „nicht messbar“ ist

- Der Server liefert `Content-Length: 14578639` (14,6 MB gzip) und `Content-Encoding: gzip`, `Vary: Accept-Encoding`.
- `reqwest` ist mit dem Feature `gzip` gebaut (`server/Cargo.toml`) und entpackt selbst. Dabei entfernt es `Content-Length` und
  `Content-Encoding` aus der Antwort; `resp.chunk()` liefert schon entpackte Bytes (`server/src/cve/http.rs`, Kommentar an der Leseschleife).
  Darum zählt der Lauf nur die entpackten Bytes (`report_unpacked`) und meldet die Übertragung als „nicht messbar“.
- Ein Zähler am Antwortstrom ohne neue Abhängigkeit ist nicht möglich: Er müsste vor dem Entpacken sitzen. Dazu müsste das automatische
  Entpacken abgeschaltet und selbst entpackt werden (z. B. mit `flate2`) – das wäre eine neue Abhängigkeit. Eine zusätzliche HEAD-Anfrage
  für `Content-Length` wäre möglich, kostet aber eine zweite Anfrage je Lauf und ist nur eine Schätzung. Verhalten deshalb unverändert.

## Warum nur wenige Läufe mit 304 enden

- Der Tracker liefert keinen `ETag`, aber `Last-Modified`; der Server sendet `If-Modified-Since` mit dem gespeicherten Wert
  (`server/src/cve/debian.rs`, `fetch`).
- Gemessen: `Last-Modified: Wed, 11 Nov 2026 22:03:06 GMT` blieb bei zwei Abfragen kurz nacheinander gleich, `Cache-Control: max-age=3600`.
  Die Datei wird also etwa stündlich neu erzeugt. Bei einem Intervall von 60 Minuten liegt zwischen zwei Läufen fast immer eine neue Version:
  Antwort 200 ist dann korrekt, 304 nur, wenn der Tracker in der Zwischenzeit nichts neu erzeugt hat.
- Das ist kein Fehler im Server. Ein längeres Intervall würde den Anteil von 304 erhöhen, aber Aktualität kosten; keine Änderung.
