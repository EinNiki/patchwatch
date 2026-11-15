#!/usr/bin/env bash
# Installiert patchwatch (Server + Web-Oberfläche) als systemd-Dienste, ohne Docker.
#
#   Erst bauen (als normaler Benutzer, im Repository):
#     cargo build --release --locked -p patchwatch-server
#     (cd web && npm ci && npm run build)
#   Dann installieren (als root):
#     sudo deploy/systemd/install.sh [--prefix /opt/patchwatch] [--start]
#   Entfernen (Konfiguration und Daten bleiben): sudo deploy/systemd/install.sh --uninstall
#
# Voraussetzungen: systemd, Node.js 22 (nur zum Betrieb der Oberfläche), PostgreSQL 15+ (Zugang in der Env-Datei).
set -euo pipefail

PREFIX=/opt/patchwatch
START=0
UNINSTALL=0
while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX=${2:?--prefix braucht einen Pfad}; shift 2 ;;
    --start) START=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "Unbekannte Option: $1" >&2; exit 2 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "Bitte als root ausführen (sudo $0 …)." >&2; exit 1; }
command -v systemctl >/dev/null || { echo "systemd (systemctl) fehlt." >&2; exit 1; }

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
UNITS=/etc/systemd/system

if [ "$UNINSTALL" -eq 1 ]; then
  systemctl disable --now patchwatch.target patchwatch-web.service patchwatch-server.service 2>/dev/null || true
  rm -f "$UNITS/patchwatch-server.service" "$UNITS/patchwatch-web.service" "$UNITS/patchwatch.target"
  rm -rf "$PREFIX"
  systemctl daemon-reload
  echo "Entfernt. /etc/patchwatch und der Benutzer patchwatch bleiben bestehen."
  exit 0
fi

BIN="$ROOT/target/release/patchwatch-server"
WEB="$ROOT/web/.next/standalone"
[ -x "$BIN" ] || { echo "Fehlt: $BIN. Erst bauen: cargo build --release --locked -p patchwatch-server" >&2; exit 1; }
[ -f "$WEB/server.js" ] || { echo "Fehlt: $WEB/server.js. Erst bauen: (cd web && npm ci && npm run build)" >&2; exit 1; }
NODE=$(command -v node || true)
[ -n "$NODE" ] || { echo "Node.js fehlt (wird für die Oberfläche gebraucht)." >&2; exit 1; }
NODE=$(readlink -f "$NODE")

id patchwatch >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin patchwatch

install -d -m 0755 "$PREFIX" "$PREFIX/bin"
install -m 0755 "$BIN" "$PREFIX/bin/patchwatch-server"
# Oberfläche: eigenständiges Next.js-Paket plus statische Dateien; der Zwischenspeicher zeigt auf /var/cache (CacheDirectory des Dienstes).
rm -rf "$PREFIX/web"
cp -a "$WEB" "$PREFIX/web"
mkdir -p "$PREFIX/web/.next"
rm -rf "$PREFIX/web/.next/static" "$PREFIX/web/.next/cache"
cp -a "$ROOT/web/.next/static" "$PREFIX/web/.next/static"
[ -d "$ROOT/web/public" ] && cp -a "$ROOT/web/public" "$PREFIX/web/public"
ln -s /var/cache/patchwatch-web "$PREFIX/web/.next/cache"
chown -R root:root "$PREFIX"

install -d -m 0750 -o root -g patchwatch /etc/patchwatch
if [ ! -e /etc/patchwatch/patchwatch.env ]; then
  install -m 0640 -o root -g patchwatch "$HERE/patchwatch.env.example" /etc/patchwatch/patchwatch.env
  echo "Neu angelegt: /etc/patchwatch/patchwatch.env (bitte Datenbank und Adresse eintragen)."
fi

for u in patchwatch-server.service patchwatch-web.service; do
  sed -e "s|@PREFIX@|$PREFIX|g" -e "s|@NODE@|$NODE|g" "$HERE/$u" >"$UNITS/$u"
  chmod 0644 "$UNITS/$u"
done
install -m 0644 "$HERE/patchwatch.target" "$UNITS/patchwatch.target"
systemctl daemon-reload
systemctl enable patchwatch.target patchwatch-server.service patchwatch-web.service >/dev/null

if [ "$START" -eq 1 ]; then
  systemctl restart patchwatch.target
  echo "Gestartet. Status: systemctl status patchwatch-server patchwatch-web"
else
  echo "Installiert. Nach dem Eintragen der Datenbank in /etc/patchwatch/patchwatch.env: sudo systemctl start patchwatch.target"
fi
echo "Reverse-Proxy mit TLS: deploy/systemd/Caddyfile.example (Server 127.0.0.1:8080, Oberfläche 127.0.0.1:3000)."
