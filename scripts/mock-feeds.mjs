// Lokale Mock-Feeds für den Seed-Stack (nur Node-Standardbibliothek, keine Netzanfragen nach außen).
//
//   node scripts/mock-feeds.mjs [Port] [--demo-load=N]   (Standard 8190, oder Umgebung MOCK_FEEDS_PORT; Bindung nur 127.0.0.1)
//   --demo-load=N (oder MOCK_DEMO_LOAD=N): hängt N erzeugte Last-Demo-CVEs (CVE-2031-NNNNN, Beschreibung "[Demo-Last] …") an das
//   Debian-Paket linux/trixie an, für scripts/load-test.mjs ("3.000 CVEs je Host"). Rein erzeugt, nicht im Repo; ohne die
//   Option unverändert. Nur gegen die Wegwerf-Datenbank verwenden (danach scripts/dev-stack.sh down && up).
//
// Liefert die Demo-Dateien aus scripts/fixtures/ in der Form, die die Adapter des Servers erwarten
// (Hinweis: Statuswerte sind erfunden, die CVE-IDs sind echt; siehe README, Abschnitt "Qualitätsprüfung"):
//   GET /tracker/data/json                       Debian-Tracker; Last-Modified, 304 bei If-Modified-Since
//   GET /security/cves.json?limit=&offset=…      Ubuntu-API, paginiert (limit höchstens 20, sonst 422 wie die echte API)
//   GET /security/cves/<CVE-ID>.json             Ubuntu-Einzelabruf (404 für unbekannte IDs)
//   POST /__mode {"mode": …}  /  GET /__mode    Fehlermodus für /tracker/data/json (nur Tests, scripts/e2e-functional.mjs):
//        ok (Standard, 304 bei If-Modified-Since) | fresh (immer 200) | 304 | 503 | 503ra (503 mit Retry-After: 1) | 422 | hang
//        (antwortet nicht, bis der Client abbricht; zum Prüfen von Zeitüberschreitung und "läuft bereits")
//   GET /oval/com.ubuntu.<release>.cve.oval.xml.bz2   OVAL je Release (noble, jammy); ETag/Last-Modified, 304
// Server dazu starten mit:
//   PATCHWATCH_CVE_DEBIAN_URL=http://127.0.0.1:8190/tracker/data/json  PATCHWATCH_CVE_UBUNTU_URL=http://127.0.0.1:8190
//   PATCHWATCH_CVE_UBUNTU_OVAL_URL=http://127.0.0.1:8190/oval          (scripts/dev-stack.sh setzt das alles)
// Die OVAL-Dateien liegen unkomprimiert vor; der Adapter liest nur bz2, deshalb wird beim Start einmal mit dem
// Systemprogramm `bzip2` (oder ersatzweise Python 3) komprimiert.
import { createServer } from "node:http";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = join(dirname(fileURLToPath(import.meta.url)), "fixtures");
const args = process.argv.slice(2);
const loadArg = args.find((a) => a.startsWith("--demo-load="));
const demoLoad = Number((loadArg ?? "").split("=")[1] ?? process.env.MOCK_DEMO_LOAD ?? 0);
const port = Number(args.find((a) => !a.startsWith("--")) ?? process.env.MOCK_FEEDS_PORT ?? 8190);
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  console.error("Ungültiger Port");
  process.exit(2);
}
const MODIFIED = new Date("2026-11-11T06:00:00Z"); // feste Änderungszeit: der zweite Abruf ergibt 304
const lastModified = MODIFIED.toUTCString();

function bzip2(buf) {
  try {
    return execFileSync("bzip2", ["-c"], { input: buf, maxBuffer: 64 << 20 });
  } catch {
    const py = "import bz2,sys; sys.stdout.buffer.write(bz2.compress(sys.stdin.buffer.read()))";
    return execFileSync("python3", ["-I", "-c", py], { input: buf, maxBuffer: 64 << 20 });
  }
}

let debian = readFileSync(join(here, "debian-tracker-demo.json"));
if (demoLoad > 0) {
  if (!Number.isInteger(demoLoad) || demoLoad > 20000) { console.error("--demo-load: ganze Zahl bis 20000"); process.exit(2); }
  const d = JSON.parse(debian.toString("utf8"));
  const prio = ["low", "medium", "high"];
  for (let i = 1; i <= demoLoad; i++) {
    // Mischung: 60 % in 6.12.20..39 behoben (die Seed-Kernel 6.12.30/6.12.48 sind je nach Wert betroffen oder nicht),
    // 25 % offen, 15 % behoben erst in einer neueren Version als der installierten.
    const k = i % 20;
    const rel = k < 12 ? { status: "resolved", fixed_version: `6.12.${20 + (i % 20)}-1` } : k < 17 ? { status: "open" } : { status: "resolved", fixed_version: `6.12.${55 + (i % 5)}-1` };
    d.linux[`CVE-2031-${String(i).padStart(5, "0")}`] = {
      description: `[Demo-Last] Erzeugte Last-Demo-CVE ${i} (nicht echt).`,
      releases: { trixie: { ...rel, urgency: prio[i % 3], repositories: { trixie: "6.12.57-1", "trixie-security": "6.12.57-1" } } },
    };
  }
  debian = Buffer.from(JSON.stringify(d));
  console.log(`mock-feeds: ${demoLoad} Last-Demo-CVEs angehängt`);
}
const ubuntu = JSON.parse(readFileSync(join(here, "ubuntu-cves-demo.json"), "utf8"));
// Absteigend nach `updated_at` sortiert, wie die echte API bei sort_by=updated&order=descending.
ubuntu.cves.sort((a, b) => b.updated_at.localeCompare(a.updated_at));
const oval = Object.fromEntries(
  ["noble", "jammy"].map((rel) => {
    const body = bzip2(readFileSync(join(here, `oval-${rel}-demo.xml`)));
    return [`com.ubuntu.${rel}.cve.oval.xml.bz2`, { body, etag: `"${createHash("sha256").update(body).digest("hex").slice(0, 16)}"` }];
  }),
);

function send(res, status, body, headers = {}) {
  const buf = typeof body === "string" ? Buffer.from(body) : body;
  res.writeHead(status, { "content-length": buf.length, ...headers });
  res.end(buf);
}
const json = (res, status, obj) => send(res, status, JSON.stringify(obj), { "content-type": "application/json" });
/** True, wenn die Anfrage unverändert ist (If-Modified-Since oder If-None-Match). */
function notModified(req, etag) {
  const inm = req.headers["if-none-match"];
  if (inm && etag) return inm.split(",").map((s) => s.trim()).includes(etag);
  const ims = Date.parse(req.headers["if-modified-since"] ?? "");
  return Number.isFinite(ims) && ims >= MODIFIED.getTime();
}

const MODES = ["ok", "fresh", "304", "503", "503ra", "422", "hang"];
let mode = "ok";

const server = createServer((req, res) => {
  const url = new URL(req.url ?? "/", "http://127.0.0.1");
  const p = url.pathname;
  res.on("finish", () => console.log(`${new Date().toISOString()} ${req.method} ${p}${url.search} -> ${res.statusCode}`));
  if (p === "/__mode") {
    if (req.method === "GET") return json(res, 200, { mode });
    if (req.method !== "POST") return send(res, 405, "nur GET/POST");
    let raw = "";
    req.on("data", (c) => { raw += c; if (raw.length > 1024) req.destroy(); });
    req.on("end", () => {
      let m;
      try { m = JSON.parse(raw).mode; } catch { /* leer */ }
      if (!MODES.includes(m)) return json(res, 400, { error: `mode muss eines von ${MODES.join(", ")} sein` });
      mode = m;
      return json(res, 200, { mode });
    });
    return;
  }
  if (req.method !== "GET" && req.method !== "HEAD") return send(res, 405, "nur GET");
  if (p === "/healthz") return send(res, 200, "ok");
  if (p === "/tracker/data/json") {
    if (mode === "503") return json(res, 503, { error: "Dienst nicht verfügbar" });
    if (mode === "503ra") return send(res, 503, "{}", { "content-type": "application/json", "retry-after": "1" });
    if (mode === "422") return json(res, 422, { error: "nicht verarbeitbar" });
    if (mode === "hang") return; // keine Antwort; der Client bricht per Zeitlimit ab
    if (mode === "304") return send(res, 304, "", { "last-modified": lastModified });
    if (mode !== "fresh" && notModified(req)) return send(res, 304, "", { "last-modified": lastModified });
    return send(res, 200, debian, { "content-type": "application/json", "last-modified": lastModified });
  }
  if (p === "/security/cves.json") {
    const limit = Number(url.searchParams.get("limit") ?? 20);
    const offset = Number(url.searchParams.get("offset") ?? 0);
    if (!Number.isInteger(limit) || limit < 1 || limit > 20 || !Number.isInteger(offset) || offset < 0) {
      return json(res, 422, { error: "limit muss zwischen 1 und 20 liegen" });
    }
    return json(res, 200, { cves: ubuntu.cves.slice(offset, offset + limit), offset, limit, total_results: ubuntu.cves.length });
  }
  const single = /^\/security\/cves\/(CVE-\d{4}-\d{4,7})\.json$/.exec(p);
  if (single) {
    const c = ubuntu.cves.find((x) => x.id === single[1]);
    return c ? json(res, 200, c) : json(res, 404, { error: "nicht gefunden" });
  }
  const file = /^\/oval\/(com\.ubuntu\.[a-z]+\.cve\.oval\.xml\.bz2)$/.exec(p);
  if (file && oval[file[1]]) {
    const o = oval[file[1]];
    const h = { etag: o.etag, "last-modified": lastModified };
    if (notModified(req, o.etag)) return send(res, 304, "", h);
    return send(res, 200, o.body, { ...h, "content-type": "application/x-bzip2" });
  }
  return json(res, 404, { error: "unbekannt" });
});
server.listen(port, "127.0.0.1", () => console.log(`mock-feeds lauscht auf http://127.0.0.1:${port}`));
for (const s of ["SIGINT", "SIGTERM"]) process.on(s, () => server.close(() => process.exit(0)));
