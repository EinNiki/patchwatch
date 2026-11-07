#!/bin/sh
# Tests für die Prüflogik von agent/dist/install.sh (Fund 5). Ohne Root, ohne Netz, ohne echtes minisign:
# die Prüffunktionen werden aus dem Installer herausgezogen und gegen lokale Dateien geprüft.
#   sh agent/tests/install_test.sh
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
INSTALLER="$HERE/../dist/install.sh"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
FAILS=0
PASSES=0

ok() { PASSES=$((PASSES + 1)); }
bad() { FAILS=$((FAILS + 1)); echo "FEHLER: $*" >&2; }
expect_ok() { desc="$1"; shift; if "$@" >/dev/null 2>&1; then ok; else bad "$desc (sollte gelingen)"; fi; }
expect_fail() { desc="$1"; shift; if "$@" >/dev/null 2>&1; then bad "$desc (sollte scheitern)"; else ok; fi; }

# Bibliothek aus dem Installer holen (Text zwischen <<'PWLIB' und PWLIB).
sed -n "/<<'PWLIB'/,/^PWLIB\$/p" "$INSTALLER" | sed '1d;$d' > "$T/lib.sh"
[ -s "$T/lib.sh" ] || { echo "Bibliothek im Installer nicht gefunden" >&2; exit 1; }
# shellcheck disable=SC1091
. "$T/lib.sh"

NAME="patchwatch-agent-x86_64-linux"
mkdir "$T/dl"
printf 'echte binärdatei\n' > "$T/dl/$NAME"
GOOD="$(sha256sum "$T/dl/$NAME" | cut -d' ' -f1)"
WRONG="$(printf 'etwas anderes' | sha256sum | cut -d' ' -f1)"
OTHER_HASH="$(printf 'fremde datei' | sha256sum | cut -d' ' -f1)"

sums() { printf '%s\n' "$@" > "$T/dl/$NAME.sha256"; }

# --- Prüfsumme ---
sums "$GOOD  $NAME"
expect_ok "richtiger Hash, richtiger Name" pw_verify_checksum "$T/dl/$NAME" "$T/dl/$NAME.sha256"
sums "$GOOD *$NAME"
expect_ok "Binärmodus-Schreibweise (*Name)" pw_verify_checksum "$T/dl/$NAME" "$T/dl/$NAME.sha256"
sums "$(printf '%s' "$GOOD" | tr a-f A-F)  $NAME"
expect_ok "Großbuchstaben im Hash" pw_verify_checksum "$T/dl/$NAME" "$T/dl/$NAME.sha256"

# Fremder Dateiname: der Hash passt zur Datei, steht aber unter anderem Namen -> darf NICHT gelten.
sums "$GOOD  anderer-name-linux"
expect_fail "Hash nur unter fremdem Dateinamen" pw_verify_checksum "$T/dl/$NAME" "$T/dl/$NAME.sha256"
sums "$GOOD  x$NAME" "$GOOD  ${NAME}x" "$GOOD  ./$NAME"
expect_fail "Namen, die nur ähnlich sind" pw_verify_checksum "$T/dl/$NAME" "$T/dl/$NAME.sha256"
# Fremde Zeile mit falschem Hash daneben, eigene Zeile fehlt.
sums "$OTHER_HASH  patchwatch-agent-aarch64-linux"
expect_fail "Zeile für die Datei fehlt" pw_verify_checksum "$T/dl/$NAME" "$T/dl/$NAME.sha256"
: > "$T/dl/$NAME.sha256"
expect_fail "leere Summendatei" pw_verify_checksum "$T/dl/$NAME" "$T/dl/$NAME.sha256"
expect_fail "Summendatei fehlt" pw_verify_checksum "$T/dl/$NAME" "$T/dl/gibt-es-nicht.sha256"

# Falscher Hash unter dem richtigen Namen.
sums "$WRONG  $NAME"
expect_fail "falscher Hash" pw_verify_checksum "$T/dl/$NAME" "$T/dl/$NAME.sha256"
# Eigene Zeile falsch, fremde Zeile passt zufällig: es zählt nur die eigene.
sums "$WRONG  $NAME" "$GOOD  anderer-name-linux"
expect_fail "falscher Hash, fremde Zeile passt" pw_verify_checksum "$T/dl/$NAME" "$T/dl/$NAME.sha256"
# Widersprüchliche Einträge für denselben Namen.
sums "$GOOD  $NAME" "$WRONG  $NAME"
expect_fail "widersprüchliche Einträge" pw_verify_checksum "$T/dl/$NAME" "$T/dl/$NAME.sha256"
# Kein gültiger Hash.
sums "nichtderhash  $NAME"
expect_fail "kein gültiger Hash" pw_verify_checksum "$T/dl/$NAME" "$T/dl/$NAME.sha256"
# Die Datei wurde nach dem Hashen verändert (Austausch beim Download).
sums "$GOOD  $NAME"
printf 'manipuliert\n' > "$T/dl/$NAME"
expect_fail "veränderte Datei" pw_verify_checksum "$T/dl/$NAME" "$T/dl/$NAME.sha256"
printf 'echte binärdatei\n' > "$T/dl/$NAME"

# --- Signatur (minisign wird durch ein Skript ersetzt, das nur Schlüssel und Datei vergleicht) ---
mkdir "$T/bin"
cat > "$T/bin/minisign" <<'STUB'
#!/bin/sh
# Attrappe: gültig nur, wenn die Signaturdatei "sig:<Schlüssel>:<sha256 der Datei>" enthält.
while [ $# -gt 0 ]; do
  case "$1" in -P) pub="$2"; shift 2 ;; -m) file="$2"; shift 2 ;; -x) sig="$2"; shift 2 ;; *) shift ;; esac
done
[ "$(cat "$sig" 2>/dev/null)" = "sig:$pub:$(sha256sum "$file" | cut -d' ' -f1)" ]
STUB
chmod +x "$T/bin/minisign"
SIG="$T/dl/$NAME.minisig"
KEY="RWTestKeyOnlyForTests0000000000000000000000000000"

# Platzhalter (so wie ausgeliefert, solange kein Schlüssel eingetragen ist): immer Fehler.
expect_fail "kein Schlüssel eingetragen" env PATH="$T/bin:$PATH" sh -c ". '$T/lib.sh'; pw_verify_signature '$T/dl/$NAME' '$SIG'"
grep -q '^PW_PUBKEY="__MINISIGN_PUBLIC_KEY_NOT_CONFIGURED__"' "$INSTALLER" || bad "Platzhalter fehlt im Installer"

PW_PUBKEY="$KEY"
printf 'sig:%s:%s' "$KEY" "$GOOD" > "$SIG"
PATH_OLD="$PATH"; PATH="$T/bin:$PATH"
expect_ok "gültige Signatur" pw_verify_signature "$T/dl/$NAME" "$SIG"
printf 'sig:%s:%s' "$KEY" "$WRONG" > "$SIG"
expect_fail "Signatur einer anderen Datei" pw_verify_signature "$T/dl/$NAME" "$SIG"
printf 'sig:ANDERER:%s' "$GOOD" > "$SIG"
expect_fail "Signatur mit fremdem Schlüssel" pw_verify_signature "$T/dl/$NAME" "$SIG"
rm -f "$SIG"
expect_fail "Signaturdatei fehlt" pw_verify_signature "$T/dl/$NAME" "$SIG"
: > "$SIG"
expect_fail "Signaturdatei leer" pw_verify_signature "$T/dl/$NAME" "$SIG"

# Summe UND Signatur: nur beides zusammen reicht.
printf 'sig:%s:%s' "$KEY" "$GOOD" > "$SIG"
sums "$GOOD  $NAME"
expect_ok "Summe und Signatur gültig" pw_verify_all "$T/dl/$NAME" "$T/dl/$NAME.sha256" "$SIG"
sums "$WRONG  $NAME"
expect_fail "Signatur gültig, Summe falsch" pw_verify_all "$T/dl/$NAME" "$T/dl/$NAME.sha256" "$SIG"
sums "$GOOD  $NAME"
printf 'kaputt' > "$SIG"
expect_fail "Summe gültig, Signatur falsch" pw_verify_all "$T/dl/$NAME" "$T/dl/$NAME.sha256" "$SIG"
PATH="$PATH_OLD"

# Ohne minisign auf dem Rechner: Fehler, nie überspringen.
mkdir "$T/nobin"
for c in sh cat sed cut sha256sum awk sort wc grep printf tr basename; do
  p="$(command -v "$c" 2>/dev/null)" && [ -x "$p" ] && ln -sf "$p" "$T/nobin/$c"
done
expect_fail "minisign nicht installiert" env PATH="$T/nobin" sh -c ". '$T/lib.sh'; PW_PUBKEY='$KEY'; pw_verify_signature '$T/dl/$NAME' '$SIG'"

# --- Austausch mit Sicherung und Rückfall ---
mkdir "$T/inst"
cat > "$T/inst/patchwatch-agent" <<'OLD'
#!/bin/sh
echo "patchwatch-agent 0.1.0"
OLD
chmod +x "$T/inst/patchwatch-agent"
cat > "$T/new-good" <<'NEW'
#!/bin/sh
echo "patchwatch-agent 0.1.3"
NEW
cat > "$T/new-broken" <<'NEW'
#!/bin/sh
exit 1
NEW
# Startet als ".new" (Probelauf), nicht aber an der Zielstelle: prüft den Rückfall nach dem Tausch.
cat > "$T/new-breaks-after-swap" <<'NEW'
#!/bin/sh
case "$0" in *.new) echo "patchwatch-agent 0.2.0" ;; *) exit 1 ;; esac
NEW

pw_apply_update "$T/new-good" "$T/inst/patchwatch-agent" && ok || bad "gutes Update"
[ "$("$T/inst/patchwatch-agent" --version)" = "patchwatch-agent 0.1.3" ] && ok || bad "neue Version nicht aktiv"
[ "$("$T/inst/patchwatch-agent.prev" --version)" = "patchwatch-agent 0.1.0" ] && ok || bad "Sicherung der alten Version fehlt"
[ ! -e "$T/inst/patchwatch-agent.new" ] && ok || bad "Zwischendatei bleibt liegen"

expect_fail "defekte neue Version wird abgelehnt" pw_apply_update "$T/new-broken" "$T/inst/patchwatch-agent"
[ "$("$T/inst/patchwatch-agent" --version)" = "patchwatch-agent 0.1.3" ] && ok || bad "alte Version nach abgelehntem Update verändert"

expect_fail "Version, die nach dem Tausch nicht startet" pw_apply_update "$T/new-breaks-after-swap" "$T/inst/patchwatch-agent"
[ "$("$T/inst/patchwatch-agent" --version)" = "patchwatch-agent 0.1.3" ] && ok || bad "kein Rückfall auf die vorherige Version"

# --- Hauptversion beim automatischen Update (curl-Attrappe liefert die Weiterleitungs-URL) ---
mkdir "$T/curlbin"
cat > "$T/curlbin/curl" <<'STUB'
#!/bin/sh
printf '%s' "$FAKE_LATEST_URL"
STUB
chmod +x "$T/curlbin/curl"
latest() { env PATH="$T/curlbin:$PATH" FAKE_LATEST_URL="$1" sh -c ". '$T/lib.sh'; pw_latest_in_major https://example.invalid/releases 0"; }
[ "$(latest https://example.invalid/releases/tag/v0.4.7)" = "v0.4.7" ] && ok || bad "neueste Version derselben Hauptversion"
expect_fail "andere Hauptversion wird nicht automatisch geladen" latest https://example.invalid/releases/tag/v1.0.0
expect_fail "unerwartete Versionsangabe" latest https://example.invalid/releases/tag/latest
expect_fail "Versionsangabe mit Anhang" latest "https://example.invalid/releases/tag/v0.4.7;rm"

# --- Test-Lauf nach Installation/Update: abgelehnter Token ist kein "erster Lauf fehlgeschlagen" ---
mkdir "$T/sysbin"
cat > "$T/sysbin/systemctl" <<'STUB'
#!/bin/sh
# Attrappe: "start" scheitert, wenn FAKE_START_FAIL=1; "show" liefert FAKE_EXEC_STATUS.
case "$1" in
  start) [ "${FAKE_START_FAIL:-0}" = 1 ] && exit 1; exit 0 ;;
  show) printf '%s\n' "${FAKE_EXEC_STATUS:-0}" ;;
esac
STUB
chmod +x "$T/sysbin/systemctl"
testrun() { env PATH="$T/sysbin:$PATH" FAKE_START_FAIL="$1" FAKE_EXEC_STATUS="$2" sh -c ". '$T/lib.sh'; pw_test_run"; }
testrun 0 0; [ $? -eq 0 ] && ok || bad "Test-Lauf ok soll 0 liefern"
testrun 1 4; [ $? -eq 4 ] && ok || bad "abgelehnter Token (Exit 4) soll 4 liefern"
testrun 1 2; [ $? -eq 1 ] && ok || bad "anderer Fehler soll 1 liefern"
testrun 1 ""; [ $? -eq 1 ] && ok || bad "unbekannter Status soll 1 liefern"
# Updater und Installer unterscheiden die drei Ausgänge und nennen set-token.
grep -q 'Update ok, aber der Server lehnt den Token ab' "$INSTALLER" && ok || bad "Updater meldet abgelehnten Token nicht getrennt"
grep -q 'Update ok, Report gesendet' "$INSTALLER" && ok || bad "Updater meldet erfolgreichen Report nicht"
grep -q 'sudo patchwatch-agent set-token' "$INSTALLER" && ok || bad "Hinweis auf set-token fehlt"
# Token und Konfiguration werden bei Update/Neuinstallation nicht überschrieben.
grep -q 'KEEP_TOKEN=yes' "$INSTALLER" && grep -q 'if \[ "\$KEEP_TOKEN" = no \]; then' "$INSTALLER" && ok || bad "vorhandene Token-Datei wird nicht geschont"
grep -q 'if \[ ! -e /etc/patchwatch/agent.toml \]' "$INSTALLER" && ok || bad "vorhandene agent.toml wird nicht geschont"
UPD="$(sed -n '/<<UPDATER/,/^UPDATER$/p' "$INSTALLER")"
printf '%s' "$UPD" | grep -Eq '/etc/patchwatch/(token|agent\.toml)[^ ]* *(>|>>)|rm .*patchwatch/(token|agent)|sed -i.*(token|agent\.toml)' && bad "Updater schreibt Token oder Konfiguration" || ok
# Der Hauptdienst bekommt ein Zustandsverzeichnis für `patchwatch-agent status`.
SVC="$(sed -n "/> \/etc\/systemd\/system\/patchwatch-agent.service <<'EOF'/,/^EOF\$/p" "$INSTALLER")"
printf '%s' "$SVC" | grep -q '^StateDirectory=patchwatch-agent' && ok || bad "Hauptdienst ohne StateDirectory"
grep -q '^StateDirectory=patchwatch-agent' "$HERE/../dist/patchwatch-agent.service" && ok || bad "Unit-Datei ohne StateDirectory"

# --- Eigenschaften des Installers selbst ---
grep -Eq 'sha256sum +-c|ignore-missing' "$INSTALLER" && bad "sha256sum -c / --ignore-missing im Installer" || ok
grep -q 'latest/download/install.sh' "$INSTALLER" && bad "Installer lädt ein Skript aus latest" || ok
grep -Eq 'exec +sh .*install\.sh' "$INSTALLER" && bad "Update führt ein heruntergeladenes Skript aus" || ok
grep -q '^AUTO_UPDATE=""' "$INSTALLER" && ok || bad "automatische Updates sind nicht standardmäßig aus"
grep -q "printf 'auto_update=no" "$INSTALLER" && ok || bad "update.conf wird nicht mit auto_update=no angelegt"
grep -q 'patchwatch-agent-update --scheduled' "$INSTALLER" && ok || bad "Timer ruft den Update-Befehl nicht im geplanten Modus auf"
grep -q '"\\\$SCHEDULED" = yes \] && \[ "\\\$(conf auto_update)" != yes' "$INSTALLER" && ok || bad "geplanter Lauf prüft auto_update nicht"
# Der Timer wird nur auf ausdrücklichen Wunsch aktiviert.
grep -q 'if \[ "\$AUTO_UPDATE" = "yes" \]; then systemctl enable --now patchwatch-agent-update.timer' "$INSTALLER" && ok || bad "Update-Timer wird nicht nur auf Wunsch aktiviert"
# Der Installer verlangt Signatur-Datei und Signaturprüfung.
grep -q 'pw_verify_all "\$TMP/\$NAME"' "$INSTALLER" && ok || bad "Installer prüft nicht Summe und Signatur"
# Eine einzige Quelle: das Skript im Repo-Wurzelverzeichnis ist dieselbe Datei.
cmp -s "$INSTALLER" "$HERE/../../install.sh" && ok || bad "install.sh im Wurzelverzeichnis weicht von agent/dist/install.sh ab"
sh -n "$INSTALLER" && ok || bad "Syntaxfehler im Installer"

echo "install_test: $PASSES bestanden, $FAILS fehlgeschlagen"
[ "$FAILS" -eq 0 ]
