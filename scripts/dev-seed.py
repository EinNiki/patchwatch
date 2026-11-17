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

def digest(c):
    return "sha256:" + c * 64


def ctr(cid, name, image, image_id, repo_digest, service, project="shop", state="running", text="Up 3 hours", arch="amd64"):
    return {
        "id": cid, "name": name, "state": state, "created_unix": 1_731_500_000, "status_text": text, "image": image,
        "image_id": image_id, "repo_digests": [repo_digest] if repo_digest else [], "os": "linux", "arch": arch,
        "variant": None, "compose_project": project, "compose_service": service,
    }


# Docker-Blöcke (Schema 2, optional): web-01 läuft mit Docker, web-02 darf den Socket nicht lesen, db-01 hat Docker mit einem Container.
DOCKER = {
    "web-01": {"state": "ok", "reason": None, "containers": [
        ctr("a1b2c3d4e5f6", "shop-web-1", "nginx:latest", digest("1"), "nginx@" + digest("a"), "web"),
        ctr("b1b2c3d4e5f6", "shop-cache-1", "redis:7.2.3", digest("2"), "redis@" + digest("b"), "cache"),
        ctr("c1b2c3d4e5f6", "shop-api-1", "ghcr.io/example/api:2.4.1", digest("3"), "ghcr.io/example/api@" + digest("c"), "api"),
        ctr("d1b2c3d4e5f6", "shop-db-1", "postgres@" + digest("d"), digest("4"), "postgres@" + digest("d"), "db"),
        ctr("e1b2c3d4e5f6", "tools-1", "registry.example.org/tools/cli:1.0", digest("5"), None, "cli", project="tools", state="exited", text="Exited (0) 2 days ago"),
    ]},
    "web-02": {"state": "unavailable", "reason": "no_permission", "containers": []},
    "db-01": {"state": "ok", "reason": None, "containers": [
        ctr("f1b2c3d4e5f6", "pg-1", "postgres:16.1.2", digest("6"), "postgres@" + digest("e"), "pg", project="data"),
    ]},
}

tokens = {}
for name, rep in HOSTS:
    if name in DOCKER:
        rep = {**rep, "schema_version": 2, "docker": DOCKER[name]}
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
