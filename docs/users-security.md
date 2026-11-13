# Benutzerrechte: Sicherheitsliste

Gilt für die Einzelrechte je Benutzer (Migration 0024), den Benutzerdialog, die Benutzerliste und OIDC unter *Einstellungen*.
Maßgeblich ist immer der **Server**; die Oberfläche blendet nur aus, sperrt mit Grund und zeigt eine Vorschau.

## Modell

- Rollen (Administrator, Betreiber, Nur Lesen) sind **Vorlagen**. Jeder Benutzer hat zusätzlich optional eine eigene Rechtemenge
  (`admin_users.permissions`, `NULL` = folgt der Vorlage der Rolle). Alle bestehenden Konten behalten `NULL`: das Verhalten
  ändert sich beim Update nicht.
- Katalog: 20 Rechte in 6 Gruppen (Hosts, Agents, CVEs und Quellen, Benachrichtigungen, Einstellungen, Benutzer). Die Liste mit
  Beschriftung, Erklärung, Voraussetzungen und Kennzeichnung „sensibel“ liefert `GET /roles`; die Oberfläche erfindet nichts.
- „Geheimnisse sehen“ gibt es **nicht**: Die API liefert nie Klartext (Token, Passwörter, Client-Secret), nur „gesetzt / nicht
  gesetzt“. Darum gibt es kein Recht dafür und keinen Schalter (Test: `web/tests/structure.test.mts`). Getrennt vergeben wird nur
  das **Setzen**: `sources.secrets.write`, `channels.secrets.write`.
- Abhängigkeiten stehen an **einer** Stelle im Server (`authz::Permission::requires`, `authz::close`): Schreiben, Ausführen, Löschen
  setzen Lesen voraus; `oidc.manage` setzt `settings.read` voraus. Ein entzogenes Leserecht nimmt abhängige Rechte mit. Der
  Client spiegelt die Tabelle (`web/src/lib/roles.ts`) nur für die Schalter.
- Unbekannte Rechtenamen in gespeicherten Daten werden ignoriert und gelten als **nicht gewährt** (nie als Fehler, nie als erlaubt).

## Rechtevergabe (Schutz vor Rechteausweitung)

| Regel | Durchsetzung |
|---|---|
| Nur Rechte vergeben, die man selbst hat | `resolve_grant`: sonst 403 |
| Nur Benutzer verwalten, deren Rechte eine Teilmenge der eigenen sind (ändern, sperren, entsperren, löschen, freigeben, Passwort zurücksetzen, OIDC-Zuordnung) | `require_covers`: sonst 403 mit Klartext |
| Eigene Rechte und Rolle nicht ändern | 403 |
| Rollenwechsel (auch auf Administrator) und Vergabe oder Entzug von `users.manage`, `oidc.manage`, `audit.read`: eigenes Passwort oder frische OIDC-Anmeldung (≤ 5 Minuten) | `reauth` |
| Rechteänderung nur mit Namensbestätigung | 400 ohne passenden Namen |
| Letzter aktiver **lokaler** Benutzer mit `users.manage`: nicht löschen, sperren, Recht entziehen, Rolle wechseln | Transaktion mit Zeilensperre (`FOR UPDATE`), Test mit parallelen Anfragen |
| Rechteänderung, Sperren, Löschen, Passwort-Reset beenden alle Sitzungen des Benutzers | `end_sessions` |
| Protokolleintrag je Änderung (nur Rechtenamen, nie Werte) | `user.permissions_changed`, `user.role_changed` |

## Oberfläche

- Benutzerdialog: Vorlage (Administrator / Betreiber / Nur Lesen / Eigene) setzt die Schalter; jedes Recht ist ein `role="switch"`.
  Rechte, die man selbst nicht hat, sind gesperrt (mit Hinweis). Eigene Rechte sind gesperrt (Hinweis: ein anderer Benutzer ändert sie).
- Liste: Löschen, Sperren und Bearbeiten sind für das eigene Konto, den letzten lokalen Verwalter und Konten mit stärkeren Rechten
  `aria-disabled` mit Tooltip **und** sichtbarem Grund in der Zeile. Der Server prüft zusätzlich.
- OIDC: nur unter *Einstellungen* (`#oidc`); `/users#oidc` leitet um. Ohne `oidc.manage` steht dort ein Hinweis statt des Formulars.
  „Verbindung testen“ ist bis zum Speichern gesperrt (Grund als Tooltip und sichtbar). `PATCHWATCH_SECRET_KEY` fehlt = ruhiger Infokasten.

## Tests

- Server (`server/tests/users.rs`, `server/src/authz.rs`): Rechtematrix je Einzelrecht (Route × Recht), Abhängigkeiten auch beim
  späteren Entziehen, Vergabe nur mit Bestätigung, Betreiber und Verwalter ohne Admin-Rechte können einen Admin weder sperren noch
  löschen noch dessen Passwort zurücksetzen, keine Vergabe fremder Rechte, unbekannter Rechtename = nicht gewährt, paralleler
  „letzter Verwalter“, Sitzungsende bei Änderung, Migration lässt Bestandskonten unverändert, keine Geheimnisse in Protokoll und Antworten.
- Web (`web/tests/roles.test.mts`, `structure.test.mts`): Abhängigkeitslogik, Zusammenfassung nur mit Namen, Zeilenschutz,
  kein „Kann Geheimnisse sehen“.
- Browser (`scripts/e2e-users.mjs`): alle Dialogzustände (anlegen je Vorlage, Fehler, Bearbeiten fremd/eigen) bei 390/768/1280/1440/1920 px,
  hell und dunkel; ein Scrollbereich, Kopf und Fußleiste sichtbar, nichts abgeschnitten, axe, Löschschutz, OIDC unter Einstellungen.

## Grenzen

- Ein echter Identitätsanbieter wurde nicht geprüft; OIDC-Tests laufen gegen Nachbildungen (Server-Tests) oder gar nicht (Browser).
  Das Freigeben eines ausstehenden OIDC-Kontos ist im Browser nicht durchgespielt (dafür braucht es eine echte Anmeldung am Anbieter);
  der Server-Pfad ist getestet.
- Wer `users.manage` hat, kann Konten mit **gleichen oder weniger** Rechten verwalten, aber keine stärkeren: Zwei Verwalter mit
  gleichem Rechteumfang können sich gegenseitig sperren (gewollt; der letzte lokale Verwalter bleibt geschützt).
- Wiederherstellung bei Aussperrung: `patchwatch-server reset-admin <benutzer>` auf dem Server (siehe README, „Zugang wiederherstellen“).
