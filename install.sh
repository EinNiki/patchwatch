#!/bin/sh
# patchwatch-agent installieren: lädt das Binary aus dem GitHub Release und
# prüft die SHA256-Summe vor der Installation. Als root ausführen.
#
#   sh install.sh --server-url https://patchwatch.example.org [--version v0.1.0] [--token-file PFAD]
#
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

die() { echo "install.sh: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --server-url) SERVER_URL="${2:-}"; shift 2 ;;
    --version) VERSION="${2:-}"; shift 2 ;;
    --token-file) TOKEN_FILE="${2:-}"; shift 2 ;;
    *) die "unbekannte Option: $1" ;;
  esac
done

[ "$(id -u)" -eq 0 ] || die "bitte als root ausführen"
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
if [ -z "$TOKEN" ]; then
  # Eingabe vom Terminal (auch wenn das Skript per Pipe läuft), ohne Echo.
  if [ -r /dev/tty ]; then TTY=/dev/tty; else TTY=/dev/stdin; fi
  printf 'Agent-Token (Eingabe bleibt unsichtbar): ' >&2
  stty -echo <"$TTY" 2>/dev/null || true
  read -r TOKEN <"$TTY" || true
  stty echo <"$TTY" 2>/dev/null || true
  echo >&2
fi
[ -n "$TOKEN" ] || die "kein Token angegeben"

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

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
echo "Lade $NAME ($VERSION) ..."
fetch "$URL_BASE/$NAME" "$TMP/$NAME"
fetch "$URL_BASE/$NAME.sha256" "$TMP/$NAME.sha256"

# Erst prüfen, dann installieren. Die .sha256-Datei verweist auf $NAME.
( cd "$TMP" && sha256sum -c "$NAME.sha256" ) || die "SHA256-Prüfsumme stimmt nicht, Abbruch"

id patchwatch >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin patchwatch
install -m 0755 "$TMP/$NAME" /usr/local/bin/patchwatch-agent

install -d -m 0755 /etc/patchwatch
# Token: nur root lesbar; systemd reicht ihn per LoadCredential an den Dienst.
( umask 077; printf '%s\n' "$TOKEN" > /etc/patchwatch/token )
chown root:root /etc/patchwatch/token
chmod 0600 /etc/patchwatch/token
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

systemctl daemon-reload
systemctl enable --now patchwatch-agent.timer
# Check-in-Timer: weckt den Agent minütlich; bei checkin_enabled = false beendet er sich sofort.
systemctl enable --now patchwatch-agent-checkin.timer
echo "Test-Lauf ..."
systemctl start patchwatch-agent.service && echo "OK: erster Report gesendet" \
  || echo "Hinweis: erster Lauf fehlgeschlagen, siehe: journalctl -u patchwatch-agent" >&2
