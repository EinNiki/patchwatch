#!/bin/sh
# patchwatch-agent installieren: lädt das Binary aus dem GitHub Release und
# prüft SHA256-Summe und minisign-Signatur vor der Installation. Als root ausführen.
#
#   sh install.sh --server-url https://patchwatch.example.org [--version v0.1.0] [--token-file PFAD]
#
# Aktualisieren: einfach erneut ausführen (Server-URL und Token werden aus /etc/patchwatch übernommen) oder
# `sudo patchwatch-agent-update`. Der Befehl lädt nur das Binary (nie ein Skript), prüft Summe und Signatur und
# ersetzt die alte Datei erst danach (mit Sicherung und Rückfall). Automatische Updates sind AUS; wer sie will,
# schaltet sie mit --auto-update ein (Eintrag auto_update=yes in /etc/patchwatch/update.conf). Sie bleiben
# innerhalb der installierten Hauptversion.
#
# Voraussetzung: das Paket `minisign` (apt install minisign) und ein in dieses Skript eingetragener
# öffentlicher Schlüssel (PW_PUBKEY, siehe README "Release-Signatur einrichten").
# Der Token steht nie im Befehl (sichtbar in `ps` und in der Shell-History): Er wird ohne Echo
# abgefragt (Standard), aus einer Datei gelesen (--token-file) oder per Umgebungsvariable
# PATCHWATCH_TOKEN übergeben (nur für Automatisierung). Gespeichert wird er als
# /etc/patchwatch/token (root:root, 0600).
set -eu

REPO="EinNiki/patchwatch"
BASE="${PATCHWATCH_RELEASE_BASE:-https://github.com/$REPO/releases}"
VERSION="latest"
SERVER_URL=""
TOKEN_FILE=""
AUTO_UPDATE=""

die() { echo "install.sh: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --server-url) SERVER_URL="${2:-}"; shift 2 ;;
    --version) VERSION="${2:-}"; shift 2 ;;
    --token-file) TOKEN_FILE="${2:-}"; shift 2 ;;
    --auto-update) AUTO_UPDATE=yes; shift ;;
    --no-auto-update) AUTO_UPDATE=no; shift ;;
    *) die "unbekannte Option: $1" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "bitte als root ausführen"
# Bereits installiert: Server-URL aus der bestehenden Konfiguration übernehmen.
if [ -z "$SERVER_URL" ] && [ -r /etc/patchwatch/agent.toml ]; then
  SERVER_URL="$(sed -n 's/^server_url *= *"\(.*\)".*/\1/p' /etc/patchwatch/agent.toml | head -n 1)"
fi
[ -n "$SERVER_URL" ] || die "--server-url fehlt"
case "$SERVER_URL" in https://*) ;; *) die "server-url muss mit https:// beginnen" ;; esac
command -v systemctl >/dev/null || die "systemd wird benötigt"
command -v sha256sum >/dev/null || die "sha256sum fehlt"

case "$(uname -m)" in
  x86_64) ARCH=x86_64 ;;
  aarch64|arm64) ARCH=aarch64 ;;
  *) die "nicht unterstützte Architektur: $(uname -m)" ;;
esac

TOKEN="${PATCHWATCH_TOKEN:-}"
if [ -n "$TOKEN_FILE" ]; then
  [ -r "$TOKEN_FILE" ] || die "Token-Datei nicht lesbar: $TOKEN_FILE"
  # Nur die erste Zeile; Leerraum am Rand entfernen.
  TOKEN="$(head -n 1 "$TOKEN_FILE" | tr -d '[:space:]')"
fi
# Bereits installiert und kein neuer Token angegeben: die vorhandene Token-Datei bleibt unangetastet
# (Token ändern: `sudo patchwatch-agent set-token`).
KEEP_TOKEN=no
if [ -z "$TOKEN" ] && [ -e /etc/patchwatch/token ]; then KEEP_TOKEN=yes; fi
if [ -z "$TOKEN" ] && [ "$KEEP_TOKEN" = no ]; then
  # Eingabe vom Terminal (auch wenn das Skript per Pipe läuft), ohne Echo.
  if [ -r /dev/tty ]; then TTY=/dev/tty; else TTY=/dev/stdin; fi
  printf 'Agent-Token (Eingabe bleibt unsichtbar): ' >&2
  stty -echo <"$TTY" 2>/dev/null || true
  read -r TOKEN <"$TTY" || true
  stty echo <"$TTY" 2>/dev/null || true
  echo >&2
fi
[ -n "$TOKEN" ] || [ "$KEEP_TOKEN" = yes ] || die "kein Token angegeben"

if [ "$VERSION" = "latest" ]; then
  URL_BASE="$BASE/latest/download"
else
  URL_BASE="$BASE/download/$VERSION"
fi
NAME="patchwatch-agent-$ARCH-linux"

fetch() {
  if command -v curl >/dev/null; then curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1"
  elif command -v wget >/dev/null; then wget -q -O "$2" "$1"
  else die "curl oder wget wird benötigt"; fi
}

# Prüfbibliothek. Wird hier einmal definiert, für diesen Lauf eingebunden und für `patchwatch-agent-update`
# nach /usr/local/lib/patchwatch/verify.sh installiert (eine Quelle, kein doppelter Code).
write_lib() {
cat > "$1" <<'PWLIB'
# patchwatch: Prüffunktionen (von install.sh und patchwatch-agent-update eingebunden).
# Öffentlicher minisign-Schlüssel der Releases. Solange hier der Platzhalter steht, wird NICHTS installiert.
PW_PUBKEY="__MINISIGN_PUBLIC_KEY_NOT_CONFIGURED__"

# SHA256 einer Datei, selbst berechnet.
pw_hash() { sha256sum "$1" | cut -d' ' -f1; }

# Erwarteter Hash aus einer .sha256-Datei für genau diesen Dateinamen ($2). Zeilen: "<hash>  <name>" oder
# "<hash> *<name>". Fremde Namen zählen nicht. Genau ein eindeutiger Hash muss übrig bleiben.
pw_expected_hash() {
  _h="$(awk -v n="$2" 'NF == 2 { f = $2; sub(/^\*/, "", f); if (f == n) print tolower($1) }' "$1" | sort -u)"
  [ -n "$_h" ] || return 1
  [ "$(printf '%s\n' "$_h" | wc -l)" -eq 1 ] || return 1
  printf '%s\n' "$_h" | grep -Eq '^[0-9a-f]{64}$' || return 1
  printf '%s\n' "$_h"
}

# $1 = heruntergeladene Datei, $2 = .sha256-Datei. Der Name in der Summendatei muss dem Dateinamen entsprechen.
pw_verify_checksum() {
  _name="$(basename "$1")"
  _exp="$(pw_expected_hash "$2" "$_name")" || { echo "Keine eindeutige Prüfsumme für $_name in $(basename "$2")" >&2; return 1; }
  _got="$(pw_hash "$1")"
  [ "$_got" = "$_exp" ] || { echo "SHA256 von $_name stimmt nicht mit der Summendatei überein" >&2; return 1; }
}

# $1 = Datei, $2 = .minisig. Ohne eingetragenen Schlüssel oder ohne minisign schlägt die Prüfung fehl (nie überspringen).
pw_verify_signature() {
  case "$PW_PUBKEY" in
    __MINISIGN_PUBLIC_KEY_NOT_CONFIGURED__) echo "Signaturprüfung nicht eingerichtet: PW_PUBKEY fehlt (README: Release-Signatur einrichten)" >&2; return 1 ;;
  esac
  command -v minisign >/dev/null 2>&1 || { echo "minisign fehlt (apt install minisign)" >&2; return 1; }
  [ -s "$2" ] || { echo "Signaturdatei fehlt: $(basename "$2")" >&2; return 1; }
  minisign -V -q -P "$PW_PUBKEY" -m "$1" -x "$2" >/dev/null 2>&1 || { echo "Signatur von $(basename "$1") ungültig" >&2; return 1; }
}

# Summe UND Signatur. Beides muss stimmen.
pw_verify_all() { pw_verify_checksum "$1" "$2" && pw_verify_signature "$1" "$3"; }

# Ersetzt die Datei $2 durch $1: Sicherung als $2.prev, Probelauf der neuen Datei vor dem Tausch, Rückfall auf die
# Sicherung, wenn die neue Datei danach nicht startet.
pw_apply_update() {
  _new="$1"; _target="$2"; _stage="$2.new"; _prev="$2.prev"
  [ ! -e "$_target" ] || cp -p "$_target" "$_prev" || return 1
  install -m 0755 "$_new" "$_stage" || return 1
  "$_stage" --version >/dev/null 2>&1 || { rm -f "$_stage"; echo "Neue Version startet nicht, alte bleibt" >&2; return 1; }
  mv -f "$_stage" "$_target" || { rm -f "$_stage"; return 1; }
  if ! "$_target" --version >/dev/null 2>&1; then
    [ ! -e "$_prev" ] || mv -f "$_prev" "$_target"
    echo "Neue Version startet nicht, Rückfall auf die vorherige" >&2
    return 1
  fi
}

# Neueste Version innerhalb der Hauptversion $2 aus der Weiterleitung von $1/latest (Tag-URL). Gibt "vX.Y.Z" aus.
pw_latest_in_major() {
  _url="$(curl -fsSL --proto '=https' --tlsv1.2 -o /dev/null -w '%{url_effective}' "$1/latest")" || return 1
  _tag="${_url##*/}"
  printf '%s\n' "$_tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' || { echo "Unerwartete Versionsangabe" >&2; return 1; }
  [ "$(printf '%s' "${_tag#v}" | cut -d. -f1)" = "$2" ] \
    || { echo "Neueste Version $_tag gehört zu einer anderen Hauptversion als $2; bitte bewusst von Hand aktualisieren" >&2; return 1; }
  printf '%s\n' "$_tag"
}

# Test-Lauf des Dienstes. Rückgabe: 0 = Report gesendet, 4 = Server lehnt den Token ab (Exit-Code 4 des Agents),
# 1 = anderer Fehler. Aufrufer entscheiden über die Meldung; so wird ein abgelehnter Token nie als
# "erster Lauf fehlgeschlagen" gemeldet.
pw_test_run() {
  if systemctl start patchwatch-agent.service; then return 0; fi
  _st="$(systemctl show -p ExecMainStatus --value patchwatch-agent.service 2>/dev/null || true)"
  if [ "$_st" = 4 ]; then return 4; fi
  return 1
}
PWLIB
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
write_lib "$TMP/verify.sh"
. "$TMP/verify.sh"
echo "Lade $NAME ($VERSION) ..."
fetch "$URL_BASE/$NAME" "$TMP/$NAME"
fetch "$URL_BASE/$NAME.sha256" "$TMP/$NAME.sha256"
fetch "$URL_BASE/$NAME.minisig" "$TMP/$NAME.minisig"

# Erst prüfen, dann installieren: Summe (selbst berechnet, Eintrag für genau diesen Dateinamen) und Signatur.
pw_verify_all "$TMP/$NAME" "$TMP/$NAME.sha256" "$TMP/$NAME.minisig" || die "Prüfung fehlgeschlagen, Abbruch"

id patchwatch >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin patchwatch
OLD_VERSION="$(/usr/local/bin/patchwatch-agent --version 2>/dev/null || true)"
install -m 0755 "$TMP/$NAME" /usr/local/bin/patchwatch-agent
NEW_VERSION="$(/usr/local/bin/patchwatch-agent --version 2>/dev/null || true)"

# Update-Befehl: lädt NUR das Binary (nie ein Skript), prüft Summe und Signatur und ersetzt die alte Datei erst danach.
install -d -m 0755 /usr/local/lib/patchwatch
write_lib /usr/local/lib/patchwatch/verify.sh
chmod 0644 /usr/local/lib/patchwatch/verify.sh
# Hauptversion festhalten: Updates (auch automatische) bleiben innerhalb davon.
MAJOR="$(printf '%s\n' "$NEW_VERSION" | sed -n 's/^[^0-9]*\([0-9][0-9]*\)\..*/\1/p')"
install -d -m 0755 /etc/patchwatch
if [ ! -e /etc/patchwatch/update.conf ]; then
  printf 'auto_update=no\nmajor=%s\n' "$MAJOR" > /etc/patchwatch/update.conf
  chmod 0644 /etc/patchwatch/update.conf
fi
# Die gerade installierte Version bestimmt die Hauptversion (bei bewusstem Versionswechsel neu gesetzt).
if [ -n "$MAJOR" ]; then
  sed -i '/^major=/d' /etc/patchwatch/update.conf
  printf 'major=%s\n' "$MAJOR" >> /etc/patchwatch/update.conf
fi
if [ "$AUTO_UPDATE" = "yes" ] || [ "$AUTO_UPDATE" = "no" ]; then
  [ "$AUTO_UPDATE" = "no" ] || [ -n "$MAJOR" ] || die "Hauptversion nicht erkennbar, automatische Updates nicht möglich"
  sed -i '/^auto_update=/d' /etc/patchwatch/update.conf
  printf 'auto_update=%s\n' "$AUTO_UPDATE" >> /etc/patchwatch/update.conf
fi
cat > /usr/local/bin/patchwatch-agent-update <<UPDATER
#!/bin/sh
# Aktualisiert den patchwatch-agent: nur das Binary der festgelegten Hauptversion, geprüft, mit Rückfall.
#   patchwatch-agent-update              neueste Version der Hauptversion aus /etc/patchwatch/update.conf
#   patchwatch-agent-update --version vX.Y.Z
#   patchwatch-agent-update --scheduled  (Timer) nur, wenn auto_update=yes
set -eu
BASE="\${PATCHWATCH_RELEASE_BASE:-$BASE}"
BIN=/usr/local/bin/patchwatch-agent
fail() { echo "patchwatch-agent-update: \$*" >&2; exit 1; }
[ "\$(id -u)" -eq 0 ] || fail "bitte als root ausführen (sudo patchwatch-agent-update)"
. /usr/local/lib/patchwatch/verify.sh
conf() { sed -n "s/^\$1=//p" /etc/patchwatch/update.conf 2>/dev/null | head -n 1; }
VERSION=""; SCHEDULED=no
while [ \$# -gt 0 ]; do
  case "\$1" in
    --version) VERSION="\${2:-}"; shift 2 ;;
    --scheduled) SCHEDULED=yes; shift ;;
    *) fail "unbekannte Option: \$1" ;;
  esac
done
if [ "\$SCHEDULED" = yes ] && [ "\$(conf auto_update)" != yes ]; then exit 0; fi
command -v curl >/dev/null || fail "curl wird benötigt"
MAJOR="\$(conf major)"
[ -n "\$MAJOR" ] || fail "Hauptversion fehlt in /etc/patchwatch/update.conf"
if [ -z "\$VERSION" ]; then VERSION="\$(pw_latest_in_major "\$BASE" "\$MAJOR")" || fail "Version nicht bestimmbar"; fi
printf '%s\n' "\$VERSION" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+\$' || fail "ungültige Version"
[ "\$(printf '%s' "\${VERSION#v}" | cut -d. -f1)" = "\$MAJOR" ] || fail "Version \$VERSION liegt außerhalb der Hauptversion \$MAJOR"
case "\$(uname -m)" in x86_64) ARCH=x86_64 ;; aarch64|arm64) ARCH=aarch64 ;; *) fail "nicht unterstützte Architektur" ;; esac
NAME="patchwatch-agent-\$ARCH-linux"
T="\$(mktemp -d)"; trap 'rm -rf "\$T"' EXIT
for f in "\$NAME" "\$NAME.sha256" "\$NAME.minisig"; do
  curl -fsSL --proto '=https' --tlsv1.2 -o "\$T/\$f" "\$BASE/download/\$VERSION/\$f" || fail "Download fehlgeschlagen: \$f"
done
pw_verify_all "\$T/\$NAME" "\$T/\$NAME.sha256" "\$T/\$NAME.minisig" || fail "Prüfung fehlgeschlagen, nichts geändert"
pw_apply_update "\$T/\$NAME" "\$BIN" || fail "Update nicht angewendet"
echo "Aktualisiert auf \$VERSION"
# Token und Konfiguration bleiben unberührt. Test-Lauf trennt "Update fehlgeschlagen" (oben, Abbruch) von
# "Update ok, aber Token abgelehnt" und "Update ok, Report gesendet".
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  rc=0; pw_test_run || rc=\$?
  case "\$rc" in
    0) echo "Update ok, Report gesendet." ;;
    4) echo "Update ok, aber der Server lehnt den Token ab (HTTP 401/403). Das Update ist nicht die Ursache. Neuen Token in der Weboberfläche unter Agents erzeugen, dann: sudo patchwatch-agent set-token" >&2 ;;
    *) echo "Update ok, aber der Test-Report ist fehlgeschlagen. Details: journalctl -u patchwatch-agent; Zustand: patchwatch-agent status" >&2 ;;
  esac
fi
UPDATER
chmod 0755 /usr/local/bin/patchwatch-agent-update

install -d -m 0755 /etc/patchwatch
# Token: nur root lesbar; systemd reicht ihn per LoadCredential an den Dienst.
if [ "$KEEP_TOKEN" = no ]; then
  ( umask 077; printf '%s\n' "$TOKEN" > /etc/patchwatch/token )
  chown root:root /etc/patchwatch/token
  chmod 0600 /etc/patchwatch/token
fi
if [ ! -e /etc/patchwatch/agent.toml ]; then
  cat > /etc/patchwatch/agent.toml <<EOF
server_url = "$SERVER_URL"
include_packages = false
timeout_secs = 30
checkin_enabled = true
checkin_interval_secs = 300
EOF
  chmod 0644 /etc/patchwatch/agent.toml
fi

cat > /etc/systemd/system/patchwatch-agent.service <<'EOF'
[Unit]
Description=patchwatch agent (einmaliger Patch- und Kernel-Report)
Documentation=https://github.com/EinNiki/patchwatch
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=patchwatch
Group=patchwatch
# Token-Datei gehört root:root 0600; systemd stellt sie dem Dienst als Credential bereit.
LoadCredential=token:/etc/patchwatch/token
# Ergebnis des letzten Laufs für `patchwatch-agent status`; gehört dem Dienstbenutzer.
StateDirectory=patchwatch-agent
StateDirectoryMode=0700
ExecStart=/usr/local/bin/patchwatch-agent --config /etc/patchwatch/agent.toml
TimeoutStartSec=120

NoNewPrivileges=yes
CapabilityBoundingSet=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallFilter=@system-service
EOF
cat > /etc/systemd/system/patchwatch-agent.timer <<'EOF'
[Unit]
Description=patchwatch agent täglich um 12:00

[Timer]
OnCalendar=*-*-* 12:00:00
RandomizedDelaySec=30min
Persistent=true

[Install]
WantedBy=timers.target
EOF

cat > /etc/systemd/system/patchwatch-agent-checkin.service <<'EOF'
[Unit]
Description=patchwatch agent Check-in (sendet nur auf Anfrage des Servers einen Report)
Documentation=https://github.com/EinNiki/patchwatch
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=patchwatch
Group=patchwatch
# Token-Datei gehört root:root 0600; systemd stellt sie dem Dienst als Credential bereit.
LoadCredential=token:/etc/patchwatch/token
# Zeitstempel des letzten Check-ins (Intervall aus agent.toml); gehört dem Dienstbenutzer.
StateDirectory=patchwatch-agent
StateDirectoryMode=0700
ExecStart=/usr/local/bin/patchwatch-agent checkin --config /etc/patchwatch/agent.toml
TimeoutStartSec=120

NoNewPrivileges=yes
CapabilityBoundingSet=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallFilter=@system-service
EOF
cat > /etc/systemd/system/patchwatch-agent-checkin.timer <<'EOF'
[Unit]
Description=patchwatch agent Check-in (Intervall: checkin_interval_secs in agent.toml)

[Timer]
# Der Timer weckt den Agent minütlich; ob ein Check-in fällig ist, entscheidet der Agent anhand des Intervalls.
OnCalendar=minutely
RandomizedDelaySec=15
AccuracySec=1s

[Install]
WantedBy=timers.target
EOF

# Automatische Updates (nur auf Wunsch, Standard AUS): wöchentlich als root, nur das Binary der festen Hauptversion.
if [ "$AUTO_UPDATE" = "yes" ]; then
  cat > /etc/systemd/system/patchwatch-agent-update.service <<'EOF'
[Unit]
Description=patchwatch agent aktualisieren
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/patchwatch-agent-update --scheduled
EOF
  cat > /etc/systemd/system/patchwatch-agent-update.timer <<'EOF'
[Unit]
Description=patchwatch agent wöchentlich auf Updates prüfen

[Timer]
OnCalendar=weekly
RandomizedDelaySec=6h
Persistent=true

[Install]
WantedBy=timers.target
EOF
elif [ "$AUTO_UPDATE" = "no" ]; then
  systemctl disable --now patchwatch-agent-update.timer 2>/dev/null || true
  rm -f /etc/systemd/system/patchwatch-agent-update.service /etc/systemd/system/patchwatch-agent-update.timer
fi

systemctl daemon-reload
if [ "$AUTO_UPDATE" = "yes" ]; then systemctl enable --now patchwatch-agent-update.timer; fi
systemctl enable --now patchwatch-agent.timer
# Check-in-Timer: weckt den Agent minütlich; bei checkin_enabled = false beendet er sich sofort.
systemctl enable --now patchwatch-agent-checkin.timer
echo "Test-Lauf ..."
rc=0; pw_test_run || rc=$?
case "$rc" in
  0) echo "OK: erster Report gesendet" ;;
  4) echo "Hinweis: Installation ok, aber der Server lehnt den Token ab (HTTP 401/403). Neuen Token in der Weboberfläche unter Agents erzeugen, dann: sudo patchwatch-agent set-token" >&2 ;;
  *) echo "Hinweis: erster Lauf fehlgeschlagen, siehe: journalctl -u patchwatch-agent" >&2 ;;
esac
if [ -n "$OLD_VERSION" ] && [ "$OLD_VERSION" != "$NEW_VERSION" ]; then
  echo "Aktualisiert: $OLD_VERSION -> $NEW_VERSION"
else
  echo "Installiert: $NEW_VERSION"
fi
echo "Später aktualisieren: sudo patchwatch-agent-update"
