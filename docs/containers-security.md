# Docker-Container und Image-Versionen: Sicherheitsliste

Gilt für die optionale Docker-Erfassung des Agents (Migration 0028), die Registry-Prüfung im Server und die Anzeige. Maßgeblich ist
immer der **Server** und der **Agent-Code**; die Oberfläche zeigt nur an.

## Datenfluss

```
Docker (Socket oder Socket-Proxy) --GET--> Agent --HTTPS POST /api/v1/report (Block "docker")--> Server --GET/HEAD--> Registry
                                                                              Server --> Datenbank --> Oberfläche (nur Anzeige)
```

- **Agent → Docker:** nur `GET /containers/json` und `GET /images/<id>/json` (Pfad-Positivliste im Client, getestet mit
  abgelehnten Pfaden wie `/containers/x/exec`, `/containers/x/json`, `/images/create`). Kein Schreibzugriff, keine Methode außer
  `GET`. Antwort höchstens 8 MiB, Zeitlimit 5 s; die Antwort wird in **eigene, schmale Strukturen** gelesen (kein Durchreichen).
- **Agent → Server:** Name, Container-ID (12 Zeichen), Zustand, Erstellzeit, Statustext (bereinigt, ≤ 64 Zeichen), Image wie
  angegeben, Image-ID, `RepoDigests` (≤ 8), Plattform, `com.docker.compose.project` und `.service`; höchstens 500 Container.
  **Nie:** Umgebungsvariablen, Mounts, Befehle, übrige Labels, Netzwerk, Logs. Test mit einer Fixture, die solche Felder mit
  Erkennungswörtern enthält: kein Wort davon im serialisierten Bericht.
- **Server → Registry:** anonym, nur https, nur `docker.io` (`registry-1.docker.io`, Token von `auth.docker.io`), `ghcr.io`,
  `quay.io`. Keine Anmeldedaten, keine privaten Registries.
- **Server → Oberfläche:** Anzeige und ein Text zum Kopieren. Es gibt **keine** Route, die ein Image zieht, einen Container
  startet, stoppt oder ändert, und keine, die einen Befehl ausführt.

## Annahmen

- **Opt-in:** `docker_enabled = false` ist der Standard. Ist es aus, greift der Agent **nicht** auf den Socket zu (Test mit
  Zugriffszähler).
- **Docker-Zugriff ist Vertrauen:** Wer den Docker-Socket lesen darf, ist meist in der Gruppe `docker`, und die ist faktisch Root.
  Darum empfiehlt die Doku einen **Socket-Proxy** (nur `CONTAINERS` und `IMAGES`, nur Lesen, nur Loopback). Der Agent akzeptiert für
  TCP nur Loopback-Adressen. `install.sh` führt `usermod -aG docker patchwatch` nie von selbst aus, sondern nur nach ausdrücklichem
  „ja“ auf einem Terminal.
- **Die Meldung des Agents ist Eingabe:** Der Server prüft Namen, Referenzen, Digests (`sha256:` + 64 Hexzeichen),
  Compose-Namen (`^[A-Za-z0-9._-]{1,64}$`) und Längen und verwirft fremde Felder beim Einlesen (kein `flatten`).
- **Befehl zum Kopieren:** nur mit gültigem Dienstnamen; sonst wird kein Befehl angezeigt (Test mit
  `evil; rm -rf /`).
- **Registry-Antworten sind Eingabe:** Manifeste ≤ 1 MiB, Tag-Listen ≤ 4 MiB, Token ≤ 16 KiB; Weiterleitungen werden nicht
  befolgt; Auflösung und Adressprüfung wie bei den CVE-Quellen (keine Loopback-, Link-Local- oder private Ziele, gepinnte
  Verbindung, kein Proxy); `Link`-Kopfzeilen der Tag-Liste nur innerhalb desselben Repositorys.

## Grenzen

- **Abruflimit Docker Hub:** anonym 100 Pulls je 6 Stunden und IPv4-Adresse bzw. IPv6-/64; `HEAD` zählt nicht, `GET` zählt
  (docs.docker.com/docker-hub/usage/pulls). Zu `tags/list` und zum Token-Abruf steht dort nichts, sie werden als zählend
  behandelt. Budget von patchwatch: höchstens 60 zählende Abrufe je 6 Stunden, aus `container_image_checks.get_count`
  berechnet (neustartfest); darüber „später geprüft“. Befindet sich dieselbe IP-Adresse hinter einer gemeinsamen NAT mit anderen
  Docker-Hub-Nutzern, kann das Limit früher erreicht sein; dann erscheint ein Fehler mit Klartext, nie ein falsches „aktuell“.
- **Gleitende Tags:** Der Vergleich beruht auf Digests. Ein Index kann sich für eine andere Plattform ändern, ohne dass das
  Image des Hosts betroffen ist; patchwatch prüft deshalb das Manifest der Host-Plattform. Ist sie nicht bestimmbar, steht
  „für die Plattform des Hosts nicht bestätigt“.
- **Feste Versionen:** Es wird nur verglichen, was sicher vergleichbar ist (mindestens drei Zahlenglieder, gleiches Präfix und
  gleiche Variante, keine Vorabversionen). Ist die Tag-Liste nach 5 Seiten nicht zu Ende, gilt sie als unvollständig.
- **Startzeit:** wird nicht erfasst (siehe README). Mehr als 500 Container werden nicht gemeldet.
- **Aussagekraft:** Ein neueres Image ist ein Hinweis, keine Sicherheitsbewertung; es ändert weder den Host-Status noch eine
  CVE-Bewertung.
- **Nicht von hier aus prüfbar gewesen:** echte Registries, echte Docker-Hosts, das Verhalten des Docker-Sockets unter der
  gehärteten systemd-Unit (`ProtectSystem=strict`), das tatsächliche Zählverhalten von `tags/list` und Token bei Docker Hub.

## Rechte

`containers.read` (Container und Bewertung sehen, auch die Zeile in der Hostliste) und `containers.check` (Prüfung anstoßen,
setzt `containers.read` voraus). Jede Route nennt ihr Recht (Rechte-Matrix im Test `server/tests/users.rs`); der Anstoß braucht
zusätzlich das CSRF-Token, ist je Konto begrenzt (6 je Minute) und je Image auf 5 Minuten Abstand.
