// Lasttest der Listen: je Route 10 Runden mit 50 gleichzeitigen Anfragen (nur fetch, keine Abhängigkeit). Ausgabe: Median, p95
// und Maximum je Route als Markdown-Tabelle, dazu der Arbeitsspeicher (VmRSS) des Servers vor und nach dem Lauf.
//
//   scripts/dev-stack.sh restart-server        # davor; für den Lauf TRUST_PROXY setzen (siehe unten)
//   PW_PWFILE=<Admin-Passwort-Datei> [PW_API=http://127.0.0.1:8091] [PW_USER=admin] [PW_PIDFILE=<server.pid>]
//   [PW_ROUNDS=10] [PW_CONCURRENCY=50] node scripts/load-test.mjs
//
// Rate-Limit: die API erlaubt 600 Anfragen/min je Client-IP. Ein Lauf braucht 2.500+; damit das Limit nicht die Messung
// verfälscht, startet man den Wegwerf-Server mit `export PATCHWATCH_TRUST_PROXY=true` (restart-server erbt es), und das Skript
// schickt je Anfrage eine eigene X-Forwarded-For-Adresse (50 verschiedene "Clients"). Nur gegen den Wegwerf-Stack, nie hinter
// einem echten Proxy. Meldet das Skript 429, ist TRUST_PROXY nicht gesetzt: dann ist das Ergebnis ungültig (Exit 2).
// Der PID-Pfad steht standardmäßig in $PW_STACK_DIR/server.pid. Exit 1, wenn eine Antwort nicht 2xx ist.
//
// Für "3.000 CVEs je Host": Mock mit `node scripts/mock-feeds.mjs 8190 --demo-load=3000` starten (erzeugte Demo-CVEs, nicht im
// Repo), dann einen Debian-Abruf auslösen (POST /api/v1/feeds/debian/run); danach dieses Skript.
import { readFileSync } from "node:fs";

const API = process.env.PW_API ?? "http://127.0.0.1:8091";
const USER = process.env.PW_USER ?? "admin";
const PW = readFileSync(process.env.PW_PWFILE, "utf8").trim();
const ROUNDS = Number(process.env.PW_ROUNDS ?? 10);
const CONC = Number(process.env.PW_CONCURRENCY ?? 50);
const pidfile = process.env.PW_PIDFILE ?? (process.env.PW_STACK_DIR ? `${process.env.PW_STACK_DIR}/server.pid` : null);

const rss = () => {
  try {
    const pid = readFileSync(pidfile, "utf8").trim();
    const m = /VmRSS:\s+(\d+) kB/.exec(readFileSync(`/proc/${pid}/status`, "utf8"));
    return m ? Math.round(Number(m[1]) / 1024) : null;
  } catch { return null; }
};

const r0 = await fetch(`${API}/api/v1/auth/login`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ username: USER, password: PW }) });
if (r0.status !== 200) { console.error(`Anmeldung fehlgeschlagen (${r0.status}); davor scripts/dev-stack.sh restart-server`); process.exit(1); }
const cookie = r0.headers.getSetCookie().map((c) => c.split(";")[0]).join("; ");
const get = (path, ip) => fetch(API + path, { headers: { cookie, "x-forwarded-for": ip } });

// Host mit den meisten CVE-Einträgen für die Host-Detail-Routen.
const hostsRes = await (await get("/api/v1/hosts", "10.9.0.1")).json();
const hosts = Array.isArray(hostsRes) ? hostsRes : hostsRes.items ?? [];
const sum = (h) => (h.cve_vulnerable ?? 0) + (h.cve_fix_pending ?? 0) + (h.cve_unknown ?? 0) + (h.cve_reboot ?? 0) + (h.cve_fixed ?? 0);
const big = [...hosts].sort((a, b) => sum(b) - sum(a))[0];
if (!big) { console.error("keine Hosts"); process.exit(1); }

const routes = [
  ["GET /hosts", "/api/v1/hosts"],
  ["GET /cves (Standard)", "/api/v1/cves"],
  ["GET /cves?affects=all", "/api/v1/cves?affects=all"],
  ["GET /cves?affects=all&limit=500", "/api/v1/cves?affects=all&limit=500"],
  [`GET /hosts/{id} (${sum(big)} CVE-Einträge)`, `/api/v1/hosts/${big.id}`],
  ["GET /hosts/{id}/cves (Standard, 100)", `/api/v1/hosts/${big.id}/cves`],
  ["GET /hosts/{id}/cves?limit=1000", `/api/v1/hosts/${big.id}/cves?limit=1000`],
  ["GET /feeds", "/api/v1/feeds"],
];

const q = (a, p) => { const s = [...a].sort((x, y) => x - y); return s[Math.min(s.length - 1, Math.ceil(p * s.length) - 1)]; };
const rssBefore = rss();
const rows = [];
let bad = 0, limited = 0, ipN = 0;
for (const [name, path] of routes) {
  const times = [];
  for (let r = 0; r < ROUNDS; r++) {
    await Promise.all(Array.from({ length: CONC }, async () => {
      const ip = `10.${(ipN >> 16) & 255}.${(ipN >> 8) & 255}.${ipN++ & 255}`;
      const t0 = performance.now();
      try {
        const res = await get(path, ip);
        await res.arrayBuffer();
        times.push(performance.now() - t0);
        if (res.status === 429) limited++;
        else if (res.status >= 300) { bad++; if (bad <= 5) console.error(`Antwort ${res.status} für ${path}`); }
      } catch (e) { bad++; times.push(performance.now() - t0); console.error(`Fehler ${path}: ${e.message}`); }
    }));
  }
  rows.push({ name, n: times.length, med: q(times, 0.5), p95: q(times, 0.95), max: Math.max(...times) });
}
const rssAfter = rss();

console.log(`| Route | Anfragen | Median (ms) | p95 (ms) | Maximum (ms) |\n|---|---:|---:|---:|---:|`);
for (const r of rows) console.log(`| ${r.name} | ${r.n} | ${Math.round(r.med)} | ${Math.round(r.p95)} | ${Math.round(r.max)} |`);
console.log(`\nServer-RSS vorher/nachher: ${rssBefore ?? "?"} MB / ${rssAfter ?? "?"} MB`);
console.log(`Host für die Detailrouten: ${sum(big)} CVE-Einträge; ${CONC} gleichzeitig x ${ROUNDS} Runden je Route`);
if (limited) { console.error(`${limited} Antworten 429: PATCHWATCH_TRUST_PROXY=true fehlt, Messung ungültig`); process.exit(2); }
const slow = rows.filter((r) => r.p95 > 1000);
if (slow.length) console.log(`HINWEIS p95 über 1 s: ${slow.map((r) => r.name).join("; ")}`);
process.exit(bad ? 1 : 0);
