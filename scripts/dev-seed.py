#!/usr/bin/env python3
"""Spielt Beispieldaten über die echte API ein (nur für die lokale Entwicklung).

    PATCHWATCH_ADMIN_PASSWORD=… python3 scripts/dev-seed.py http://127.0.0.1:8080 admin

Legt Hosts an und sendet Reports (Ubuntu 22.04/24.04, Debian trixie, Proxmox 9). Läuft idempotent:
bereits vorhandene Hosts bekommen einen neuen Token und einen frischen Report.
"""
import http.cookiejar
import json
import os
import sys
import urllib.error
import urllib.request

base = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080").rstrip("/")
user = sys.argv[2] if len(sys.argv) > 2 else "admin"
password = os.environ.get("PATCHWATCH_ADMIN_PASSWORD") or sys.exit("PATCHWATCH_ADMIN_PASSWORD setzen")

jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
csrf = ""


def call(method, path, body=None, headers=None):
    h = dict(headers or {})
    if body is not None:  # JSON-Header nur mit Body (sonst lehnt der Server den leeren Body ab)
        h["content-type"] = "application/json"
    req = urllib.request.Request(base + path, method=method, headers=h, data=None if body is None else json.dumps(body).encode())
    def parse(data):
        try:
            return json.loads(data) if data else None
        except ValueError:
            return data.decode(errors="replace")

    try:
        with opener.open(req) as r:
            return r.status, parse(r.read())
    except urllib.error.HTTPError as e:
        return e.code, parse(e.read())


def admin(method, path, body=None):
    return call(method, "/api/v1" + path, body, {"x-csrf-token": csrf})


status, me = call("POST", "/api/v1/auth/login", {"username": user, "password": password})
if status != 200:
    sys.exit(f"Login fehlgeschlagen ({status})")
csrf = me["csrf_token"]


def report(host, os_id, ver, codename, pretty, running, pkg, source, version, newest_rel, newest_ver, updates, security, uptime, proxmox=None, reboot_file=False):
    return {
        "schema_version": 1, "agent_version": "0.1.0", "hostname": host, "collected_at_unix": 1,
        "os": {"id": os_id, "version_id": ver, "codename": codename, "pretty_name": pretty},
        "kernel": {
            "running_release": running,
            "running_package": {"name": pkg, "version": version, "source": source, "source_version": version},
            "newest_installed_release": newest_rel,
            "newest_installed_package": {"name": pkg, "version": newest_ver, "source": source, "source_version": newest_ver},
            "reboot_needed_kernel": version != newest_ver,
        },
        "reboot_required_file": reboot_file, "updates": {"pending": updates, "security": security},
        "uptime_seconds": uptime, "proxmox": {"version": proxmox} if proxmox else None, "packages": None,
    }


HOSTS = [
    ("web-01", report("web-01", "ubuntu", "24.04", "noble", "Ubuntu 24.04.3 LTS", "6.8.0-79-generic", "linux-image-6.8.0-79-generic", "linux-signed", "6.8.0-79.79", "6.8.0-79-generic", "6.8.0-79.79", 0, 0, 1_200_000)),
    ("web-02", report("web-02", "ubuntu", "22.04", "jammy", "Ubuntu 22.04.5 LTS", "5.15.0-100-generic", "linux-image-5.15.0-100-generic", "linux-signed", "5.15.0-100.110", "5.15.0-118-generic", "5.15.0-118.128", 14, 3, 864_000, reboot_file=True)),
    ("db-01", report("db-01", "debian", "13", "trixie", "Debian GNU/Linux 13 (trixie)", "6.12.30+deb13-amd64", "linux-image-6.12.30+deb13-amd64", "linux-signed-amd64", "6.12.30-1", "6.12.30+deb13-amd64", "6.12.30-1", 7, 0, 3_900_000)),
    ("db-02", report("db-02", "debian", "13", "trixie", "Debian GNU/Linux 13 (trixie)", "6.12.48+deb13-amd64", "linux-image-6.12.48+deb13-amd64", "linux-signed-amd64", "6.12.48-1", "6.12.57+deb13-amd64", "6.12.57-1", 2, 0, 400_000)),
    ("pve-01", report("pve-01", "debian", "13", "trixie", "Debian GNU/Linux 13 (trixie)", "6.14.11-2-pve", "proxmox-kernel-6.14.11-2-pve-signed", "proxmox-kernel-6.14", "6.14.11-2", "6.14.11-2-pve", "6.14.11-2", 5, 1, 2_000_000, proxmox="9.0.3")),
    ("backup-01", report("backup-01", "ubuntu", "24.04", "noble", "Ubuntu 24.04.3 LTS", "6.8.0-79-generic", "linux-image-6.8.0-79-generic", "linux-signed", "6.8.0-79.79", "6.8.0-79-generic", "6.8.0-79.79", 3, 0, 100)),
]

tokens = {}
for name, rep in HOSTS:
    status, r = admin("POST", "/hosts", {"name": name})
    if status == 409:  # vorhanden: Token neu erzeugen
        _, hosts = admin("GET", "/hosts")
        hid = next(h["id"] for h in hosts if h["name"] == name)
        _, r = admin("POST", f"/hosts/{hid}/rotate-token")
    tokens[name] = r["token"]
    s, _ = call("POST", "/api/v1/report", rep, {"authorization": f"Bearer {r['token']}"})
    print(f"{name:10s} report -> {s}")

# Ein Host ohne Report (Status "noch kein Report").
if admin("POST", "/hosts", {"name": "neu-01"})[0] not in (201, 409):
    print("neu-01 konnte nicht angelegt werden")

for cve, note in (("CVE-2024-1086", "nf_tables Use-after-free, Prio 1"), ("CVE-2026-99999", "")):
    s, _ = admin("PUT", f"/watchlist/{cve}", {"note": note} if note else None)
    print(f"watchlist {cve} -> {s}")
print("fertig. Feeds ggf. abrufen: POST /api/v1/feeds/refresh?wait=true")
