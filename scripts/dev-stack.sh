#!/bin/sh
# Wegwerf-Stack für Qualitätsprüfungen (layout-check, a11y, Screenshots): Postgres im Container, Server, Mock-Feeds,
# Demo-Hosts (scripts/dev-seed.py), ein Feed-Abruf gegen die Mocks und die Web-UI aus dem vorhandenen Build.
#
#   scripts/dev-stack.sh up | down | status | restart-server | restart-web
#
# up              startet alles, was noch nicht läuft (idempotent), und wartet auf den Feed-Abruf
# down            stoppt NUR die eigenen Prozesse (PID-Dateien) und entfernt den eigenen Postgres-Container
# status          zeigt, was läuft (nie das Passwort)
# restart-server  startet nur den Server neu (setzt das In-Memory-Login-Limit zurück)
# restart-web     startet nur die Web-UI neu (nach `npm --prefix web run build`)
#
# Umgebung (Standardwerte in Klammern):
#   PW_STACK_DIR     Zustand: PID-Dateien, Logs, Passwortdateien, außerhalb des Repos
#                    (${TMPDIR:-/tmp}/patchwatch-dev-stack)
#   PW_PG_NAME       Containername, muss mit "pw-night-" beginnen (pw-night-pg)
#   PW_PG_PORT       Postgres auf 127.0.0.1 (55440)
#   PW_SERVER_PORT   API (8091)     PW_WEB_PORT  UI (3300)     PW_MOCK_PORT  Mock-Feeds (8190)
#   PW_ADMIN_USER    Admin-Benutzer (admin)
#   PW_PWFILE        Admin-Passwort, chmod 600 ($PW_STACK_DIR/admin.pw); wird beim ersten Start zufällig erzeugt, nie ausgegeben
#   PW_SKIP_BUILD    1 = Server nicht neu bauen (nur den vorhandenen Build nutzen)
# Cargo: CARGO_TARGET_DIR (gemeinsamer Cache) und CARGO_BUILD_JOBS (2) werden, falls nicht gesetzt, vorbelegt.
#
# Die Feed-Adressen der eingebauten Quellen (Ubuntu, Debian, OVAL) kommen aus der Konfiguration und nutzen einen
# normalen HTTP-Client; Loopback ist dafür erlaubt. Der SSRF-Schutz gilt nur für in der UI angelegte Spiegel-Adressen
# und bleibt unverändert. Alle anderen Quellen (OSV, NVD, KEV) sind nicht angelegt, also abgeschaltet.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
STACK=${PW_STACK_DIR:-${TMPDIR:-/tmp}/patchwatch-dev-stack}
PG_NAME=${PW_PG_NAME:-pw-night-pg}
PG_PORT=${PW_PG_PORT:-55440}
SERVER_PORT=${PW_SERVER_PORT:-8091}
WEB_PORT=${PW_WEB_PORT:-3300}
MOCK_PORT=${PW_MOCK_PORT:-8190}
ADMIN_USER=${PW_ADMIN_USER:-admin}
PWFILE=${PW_PWFILE:-$STACK/admin.pw}
PGPWFILE=$STACK/pg.pw
API="http://127.0.0.1:$SERVER_PORT"
MOCK="http://127.0.0.1:$MOCK_PORT"

die() { echo "dev-stack: $*" >&2; exit 1; }

case $PG_NAME in pw-night-*) ;; *) die "PW_PG_NAME muss mit pw-night- beginnen" ;; esac

# ---- Prozesse -----------------------------------------------------------------------------------------------------

# alive <name> <cmdline-Teil>: PID-Datei vorhanden, Prozess lebt und gehört (laut cmdline) zu uns.
alive() {
  [ -f "$STACK/$1.pid" ] || return 1
  p=$(cat "$STACK/$1.pid")
  [ -r "/proc/$p/cmdline" ] || return 1
  tr '\0' ' ' < "/proc/$p/cmdline" | grep -q -- "$2"
}

# start_bg <name> <log> <Befehl…>: eigene Sitzung (setsid), damit die ganze Gruppe gestoppt werden kann.
start_bg() {
  name=$1; log=$2; shift 2
  setsid "$@" > "$log" 2>&1 < /dev/null &
  echo $! > "$STACK/$name.pid"
}

# stop_bg <name>: Gruppe beenden, bis zu 10 s warten, danach SIGKILL. Nur Prozesse aus der eigenen PID-Datei.
stop_bg() {
  [ -f "$STACK/$1.pid" ] || return 0
  p=$(cat "$STACK/$1.pid")
  if [ -d "/proc/$p" ]; then
    kill -TERM -- "-$p" 2> /dev/null || kill -TERM "$p" 2> /dev/null || true
    i=0
    while [ -d "/proc/$p" ] && [ $i -lt 20 ]; do sleep 0.5; i=$((i + 1)); done
    if [ -d "/proc/$p" ]; then kill -KILL -- "-$p" 2> /dev/null || kill -KILL "$p" 2> /dev/null || true; fi
  fi
  rm -f "$STACK/$1.pid"
}

# wait_http <url> <Sekunden> [Name]
wait_http() {
  i=0
  while [ $i -lt "$2" ]; do
    if curl -fsS -o /dev/null --max-time 3 "$1" 2> /dev/null; then return 0; fi
    sleep 1; i=$((i + 1))
  done
  die "${3:-$1} wurde nicht rechtzeitig bereit (siehe $STACK/*.log)"
}

# ---- Postgres -----------------------------------------------------------------------------------------------------

pg_state() { docker inspect -f '{{.State.Running}}' "$PG_NAME" 2> /dev/null || echo none; }

pg_up() {
  if [ ! -s "$PGPWFILE" ]; then
    (umask 077; head -c 64 /dev/urandom | od -An -tx1 | tr -d ' \n' | head -c 32 > "$PGPWFILE")
  fi
  case $(pg_state) in
    true) ;;
    false) docker start "$PG_NAME" > /dev/null ;;
    *)
      docker run -d --name "$PG_NAME" --label pw-night=1 \
        -e POSTGRES_USER=patchwatch -e "POSTGRES_PASSWORD=$(cat "$PGPWFILE")" -e POSTGRES_DB=patchwatch \
        -p "127.0.0.1:$PG_PORT:5432" postgres:17-alpine > /dev/null
      ;;
  esac
  i=0
  # pg_isready meldet beim Initialisieren kurz "bereit", obwohl der Server danach neu startet: zweimal hintereinander.
  ok=0
  while [ $i -lt 60 ]; do
    if docker exec "$PG_NAME" pg_isready -U patchwatch -d patchwatch > /dev/null 2>&1; then
      ok=$((ok + 1)); [ $ok -ge 2 ] && return 0
    else
      ok=0
    fi
    sleep 1; i=$((i + 1))
  done
  die "Postgres nicht bereit"
}

# ---- Server -------------------------------------------------------------------------------------------------------

# Gemeinsame Umgebung für Server und create-admin. Das Datenbankpasswort steht nur in der Prozessumgebung.
server_env() {
  PATCHWATCH_DATABASE_URL="postgres://patchwatch:$(cat "$PGPWFILE")@127.0.0.1:$PG_PORT/patchwatch"
  PATCHWATCH_LISTEN="127.0.0.1:$SERVER_PORT"
  PATCHWATCH_COOKIE_SECURE=false
  PATCHWATCH_ALLOWED_ORIGINS="http://127.0.0.1:$WEB_PORT,http://localhost:$WEB_PORT"
  # Nur Ubuntu (Hybridmodus mit OVAL) und Debian, alle Adressen auf den lokalen Mock.
  PATCHWATCH_CVE_SOURCES=ubuntu,debian
  PATCHWATCH_CVE_UBUNTU_MODE=hybrid
  PATCHWATCH_CVE_UBUNTU_URL=$MOCK
  PATCHWATCH_CVE_UBUNTU_OVAL_URL=$MOCK/oval
  PATCHWATCH_CVE_DEBIAN_URL=$MOCK/tracker/data/json
  PATCHWATCH_CVE_OSV_URL=$MOCK/unused/osv
  PATCHWATCH_CVE_NVD_URL=$MOCK/unused/nvd
  PATCHWATCH_CVE_KEV_URL=$MOCK/unused/kev
  PATCHWATCH_CVE_UBUNTU_PAGE_PAUSE_MS=0
  RUST_LOG=${RUST_LOG:-info}
  export PATCHWATCH_DATABASE_URL PATCHWATCH_LISTEN PATCHWATCH_COOKIE_SECURE PATCHWATCH_ALLOWED_ORIGINS \
    PATCHWATCH_CVE_SOURCES PATCHWATCH_CVE_UBUNTU_MODE PATCHWATCH_CVE_UBUNTU_URL PATCHWATCH_CVE_UBUNTU_OVAL_URL \
    PATCHWATCH_CVE_DEBIAN_URL PATCHWATCH_CVE_OSV_URL PATCHWATCH_CVE_NVD_URL PATCHWATCH_CVE_KEV_URL \
    PATCHWATCH_CVE_UBUNTU_PAGE_PAUSE_MS RUST_LOG
}

server_bin() {
  tdir=${CARGO_TARGET_DIR:-$ROOT/target}
  echo "$tdir/debug/patchwatch-server"
}

server_build() {
  [ "${PW_SKIP_BUILD:-0}" = 1 ] && return 0
  CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-2}
  CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$ROOT/target}
  PATH=$HOME/.cargo/bin:$PATH
  export CARGO_BUILD_JOBS CARGO_TARGET_DIR PATH
  echo "dev-stack: baue Server (cargo build -p patchwatch-server) ..."
  (cd "$ROOT" && timeout 1200 cargo build -p patchwatch-server > "$STACK/build.log" 2>&1) \
    || { tail -n 20 "$STACK/build.log" >&2; die "Server-Build fehlgeschlagen"; }
}

server_start() {
  bin=$(server_bin)
  [ -x "$bin" ] || die "Server-Binary fehlt: $bin"
  ( server_env; start_bg server "$STACK/server.log" "$bin" serve )
  wait_http "$API/readyz" 90 "Server"
}

ensure_admin() {
  if [ ! -s "$PWFILE" ]; then
    mkdir -p "$(dirname "$PWFILE")"
    (umask 077; head -c 96 /dev/urandom | od -An -tx1 | tr -d ' \n' | head -c 28 > "$PWFILE")
  fi
  chmod 600 "$PWFILE"
  # Der Server-Start legt ggf. einen Zufalls-Admin an; create-admin setzt Benutzer und Passwort verbindlich.
  ( server_env; PATCHWATCH_ADMIN_PASSWORD=$(cat "$PWFILE"); export PATCHWATCH_ADMIN_PASSWORD
    "$(server_bin)" create-admin "$ADMIN_USER" > "$STACK/create-admin.log" 2>&1 ) \
    || die "Admin konnte nicht angelegt werden (siehe $STACK/create-admin.log)"
}

# ---- Seed und Feed-Abruf -------------------------------------------------------------------------------------------

seed() {
  PATCHWATCH_ADMIN_PASSWORD=$(cat "$PWFILE") python3 "$ROOT/scripts/dev-seed.py" "$API" "$ADMIN_USER" > "$STACK/seed.log" 2>&1 \
    || { tail -n 5 "$STACK/seed.log" >&2; die "dev-seed.py fehlgeschlagen"; }
}

# Genau ein synchroner Abruf aller eingeschalteten Quellen gegen den Mock. Ausgabe: Quelle und Ergebnis, nie Geheimnisse.
feed_refresh() {
  PW_API=$API PW_USER=$ADMIN_USER PW_PWFILE=$PWFILE python3 -I - << 'PY'
import http.cookiejar, json, os, sys, urllib.request, urllib.error
base, user = os.environ["PW_API"], os.environ["PW_USER"]
pw = open(os.environ["PW_PWFILE"]).read().strip()
op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def call(method, path, body=None, csrf=None):
    h = {}
    if body is not None: h["content-type"] = "application/json"
    if csrf: h["x-csrf-token"] = csrf
    r = urllib.request.Request(base + path, method=method, headers=h, data=None if body is None else json.dumps(body).encode())
    try:
        with op.open(r, timeout=600) as resp: return resp.status, json.loads(resp.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")[:200]
s, me = call("POST", "/api/v1/auth/login", {"username": user, "password": pw})
if s != 200: sys.exit(f"Login fehlgeschlagen ({s})")
s, out = call("POST", "/api/v1/feeds/refresh?wait=true", None, me["csrf_token"])
if s != 200: sys.exit(f"Feed-Abruf fehlgeschlagen ({s}): {out}")
bad = 0
for r in out["results"]:
    print(f"  Quelle {r['source']}: {r['result']}" + (f" ({r['error']})" if r.get("error") else ""))
    bad += r["result"] not in ("updated", "not_modified")
sys.exit(1 if bad else 0)
PY
}

# ---- Web ----------------------------------------------------------------------------------------------------------

web_start() {
  [ -f "$ROOT/web/.next/standalone/server.js" ] || die "Kein Web-Build: npm --prefix web run build"
  # Direkt node (statt npm), damit die PID-Datei den Prozess selbst trägt und stop_bg ihn samt Kindprozess (next-server) beendet.
  ( cd "$ROOT/web" && PORT=$WEB_PORT PATCHWATCH_API_URL=$API && export PORT PATCHWATCH_API_URL \
    && start_bg web "$STACK/web.log" node scripts/start-prod.mjs )
  wait_http "http://127.0.0.1:$WEB_PORT/login" 90 "Web"
}

# ---- Unterbefehle -------------------------------------------------------------------------------------------------

cmd_up() {
  mkdir -p "$STACK"; chmod 700 "$STACK"
  command -v docker > /dev/null || die "docker fehlt"
  pg_up
  if alive mock "mock-feeds.mjs"; then :; else
    start_bg mock "$STACK/mock.log" node "$ROOT/scripts/mock-feeds.mjs" "$MOCK_PORT"
    wait_http "$MOCK/healthz" 20 "Mock-Feeds"
  fi
  fresh=0
  if alive server "patchwatch-server"; then :; else
    server_build
    ensure_admin
    server_start
    fresh=1
  fi
  # Seed und Abruf bei jedem frischen Serverstart (beides ist idempotent; der Abruf ergibt bei Unverändertem 304).
  if [ $fresh = 1 ]; then
    seed
    echo "dev-stack: Feed-Abruf gegen den Mock ..."
    feed_refresh || die "Feed-Abruf nicht erfolgreich (siehe $STACK/server.log)"
  fi
  if alive web "start-prod"; then :; else web_start; fi
  echo "dev-stack: bereit. UI http://127.0.0.1:$WEB_PORT, API $API, Benutzer $ADMIN_USER, Passwortdatei $PWFILE"
}

cmd_down() {
  stop_bg web
  stop_bg server
  stop_bg mock
  if [ "$(pg_state)" != none ]; then docker rm -f "$PG_NAME" > /dev/null; fi
  echo "dev-stack: gestoppt"
}

cmd_status() {
  for n in mock server web; do
    if [ -f "$STACK/$n.pid" ] && [ -d "/proc/$(cat "$STACK/$n.pid")" ]; then echo "$n: läuft (PID $(cat "$STACK/$n.pid"))"; else echo "$n: aus"; fi
  done
  case $(pg_state) in true) echo "postgres: läuft ($PG_NAME, 127.0.0.1:$PG_PORT)" ;; false) echo "postgres: gestoppt" ;; *) echo "postgres: nicht vorhanden" ;; esac
  for u in "$MOCK/healthz" "$API/readyz" "http://127.0.0.1:$WEB_PORT/login"; do
    if curl -fsS -o /dev/null --max-time 3 "$u" 2> /dev/null; then echo "antwortet: $u"; else echo "keine Antwort: $u"; fi
  done
}

cmd_restart_server() {
  [ -f "$PGPWFILE" ] || die "Stack läuft nicht (zuerst: up)"
  stop_bg server
  server_start
  echo "dev-stack: Server neu gestartet (Login-Limit zurückgesetzt)"
}

cmd_restart_web() {
  [ -f "$PGPWFILE" ] || die "Stack läuft nicht (zuerst: up)"
  stop_bg web
  web_start
  echo "dev-stack: Web neu gestartet"
}

case ${1:-} in
  up) cmd_up ;;
  down) cmd_down ;;
  status) cmd_status ;;
  restart-server) cmd_restart_server ;;
  restart-web) cmd_restart_web ;;
  *) echo "Verwendung: $0 up | down | status | restart-server | restart-web" >&2; exit 2 ;;
esac
