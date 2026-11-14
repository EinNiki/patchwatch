// Ausfalltest: stoppt den Postgres-Container des Wegwerf-Stacks für PW_OUTAGE_SECS Sekunden und prüft API, Browser und Erholung.
// Während des Ausfalls: API antwortet 503 mit deutschem Text ohne interne Details (Retry-After), /readyz 503, Antwort < 7 s;
// das UI zeigt eine verständliche Fehlermeldung (keine weiße Seite) und bleibt angemeldet (keine Umleitung nach /login).
// Danach: Server erholt sich ohne Neustart (gleiche PID, falls PW_SERVER_PIDFILE gesetzt), Sitzung gilt weiter, Hosts-/CVE-Zahlen
// gleich, "Erneut versuchen" lädt die Seite, die Live-Verbindung steht wieder, ein Ereignis kommt per LISTEN/NOTIFY an.
// Vorab: ein Render-Fehler (nachgestellte unerwartete API-Antwort) zeigt eine deutsche Fehlerseite statt einer leeren Seite.
// Stoppt/startet NUR den in PW_PG_CONTAINER genannten Container (muss mit "pw-night-" beginnen). Exit 1 bei Fehlern.
//   PW_MODULE=… PW_CHROME=… PW_PWFILE=<Datei mit Admin-Passwort> PW_PG_CONTAINER=pw-night-pg \
//   [PW_BASE=http://127.0.0.1:3300] [PW_API=http://127.0.0.1:8091] [PW_USER=admin] [PW_OUTAGE_SECS=30] \
//   [PW_SERVER_PIDFILE=$PW_STACK_DIR/server.pid] node scripts/e2e-outage.mjs
// Fordert für zwei Hosts je einen Report an ("Daten jetzt abrufen"), verändert sonst nichts.
import { createRequire } from "node:module";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";

const container = process.env.PW_PG_CONTAINER ?? "";
if (!/^pw-night-[a-z0-9-]+$/.test(container)) {
  console.error("PW_PG_CONTAINER muss gesetzt sein und mit pw-night- beginnen");
  process.exit(2);
}
const { chromium } = createRequire(import.meta.url)(process.env.PW_MODULE);
const pw = readFileSync(process.env.PW_PWFILE, "utf8").trim();
const user = process.env.PW_USER ?? "admin";
const base = process.env.PW_BASE ?? "http://127.0.0.1:3300";
const apiBase = process.env.PW_API ?? "http://127.0.0.1:8091";
const outageSecs = Number(process.env.PW_OUTAGE_SECS ?? 30);
const pidFile = process.env.PW_SERVER_PIDFILE;
const ok = (c, m) => { console.log(c ? "OK  " : "FAIL", m); if (!c) process.exitCode = 1; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// Begriffe, die nie in einer Fehlermeldung an Client oder UI stehen dürfen (interne Details).
const INTERNAL = /sqlx|pool|postgres|tcp|os error|connection refused|timed out|127\.0\.0\.1|55\d\d\d/i;

const docker = (...args) => execFileSync("docker", args, { stdio: ["ignore", "pipe", "pipe"], timeout: 60_000 }).toString().trim();
const pgRunning = () => { try { return docker("inspect", "-f", "{{.State.Running}}", container) === "true"; } catch { return false; } };
const serverPid = () => (pidFile && existsSync(pidFile) ? readFileSync(pidFile, "utf8").trim() : null);

// ---- API (direkt am Server, eigene Sitzung) ------------------------------------------------------------------------
let cookie = "";
let csrf = "";
async function call(method, path, body) {
  const headers = {};
  if (cookie) headers.cookie = cookie;
  if (body !== undefined) headers["content-type"] = "application/json";
  if (method !== "GET" && csrf) headers["x-csrf-token"] = csrf;
  const t0 = Date.now();
  try {
    const r = await fetch(`${apiBase}${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(30_000) });
    const text = await r.text();
    let json = null;
    try { json = JSON.parse(text); } catch { /* kein JSON */ }
    return { status: r.status, json, text, ms: Date.now() - t0, headers: r.headers };
  } catch (e) {
    return { status: 0, json: null, text: String(e), ms: Date.now() - t0, headers: new Headers() };
  }
}
async function login() {
  const r = await call("POST", "/api/v1/auth/login", { username: user, password: pw });
  if (r.status !== 200) throw new Error(`API-Anmeldung fehlgeschlagen (${r.status})`);
  cookie = (r.headers.get("set-cookie") ?? "").split(";")[0];
  csrf = r.json.csrf_token;
}
const count = (j) => (Array.isArray(j) ? j.length : (j?.total ?? j?.items?.length ?? -1));
async function counts() {
  const h = await call("GET", "/api/v1/hosts");
  const c = await call("GET", "/api/v1/cves?affects=all&limit=500");
  return { hosts: h.status === 200 ? count(h.json) : `HTTP ${h.status}`, cves: c.status === 200 ? count(c.json) : `HTTP ${c.status}` };
}
async function waitReady(maxSecs) {
  const t0 = Date.now();
  while (Date.now() - t0 < maxSecs * 1000) {
    const r = await call("GET", "/readyz");
    if (r.status === 200) return (Date.now() - t0) / 1000;
    await sleep(500);
  }
  return null;
}

// ---- Browser --------------------------------------------------------------------------------------------------------
const browser = await chromium.launch({ executablePath: process.env.PW_CHROME, args: ["--no-sandbox"] });
let stopped = false;
try {
  if (!pgRunning()) throw new Error(`Container ${container} läuft nicht`);
  await login();
  const before = await counts();
  const pidBefore = serverPid();
  ok(typeof before.hosts === "number" && before.hosts > 0, `vorher: ${before.hosts} Hosts, ${before.cves} CVEs`);

  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, colorScheme: "light" });
  const page = await ctx.newPage();
  const pageErrors = [];
  page.on("pageerror", (e) => pageErrors.push(String(e)));
  await page.goto(`${base}/login`);
  await page.getByLabel("Benutzername").fill(user);
  await page.getByLabel("Passwort").fill(pw);
  await page.getByRole("button", { name: "Anmelden", exact: true }).click();
  await page.waitForURL((u) => !u.pathname.startsWith("/login"));
  await page.goto(`${base}/`);
  await page.getByRole("table").first().waitFor({ timeout: 15_000 });
  const liveIndicator = page.getByRole("status").filter({ hasText: /^(Live|Verbinde …|Getrennt, verbinde neu …)$/ }).first();
  await liveIndicator.filter({ hasText: /^Live$/ }).waitFor({ timeout: 20_000 });
  ok(true, "Browser angemeldet, Host-Liste geladen, Live verbunden");

  // Render-Fehler (unerwartete API-Antwort, nachgestellt per page.route) statt der leeren Next-Seite „Application error“:
  // (a) nur die Seite wirft (CVE-Liste): Fehler im App-Rahmen, Navigation bleibt; (b) der Rahmen selbst wirft (Host-Liste
  // nutzt auch die Seitenleiste): ganzseitige Fehlerseite. Beide mit „Erneut versuchen“.
  for (const [label, re, path, title, nav] of [
    ["Render-Fehler der Seite", /\/api\/v1\/cves\?/, "/cves", "Diese Seite konnte nicht angezeigt werden", true],
    ["Render-Fehler im Rahmen", /\/api\/v1\/hosts(\?.*)?$/, "/", "patchwatch konnte nicht angezeigt werden", false],
  ]) {
    const crash = await ctx.newPage();
    await crash.route(re, (r) => r.fulfill({ status: 200, contentType: "application/json", body: '{"unerwartet":true}' }));
    await crash.goto(`${base}${path}`);
    const crashAlert = crash.getByRole("alert").filter({ hasText: title }).first();
    const crashShown = await crashAlert.waitFor({ timeout: 15_000 }).then(() => true, () => false);
    const crashBody = (await crash.locator("body").innerText()).trim();
    ok(crashShown && !/Application error|couldn.t load/i.test(crashBody), `${label}: Fehlerseite „${title}“: ${JSON.stringify(crashBody.slice(0, 90))}`);
    ok(await crash.getByRole("button", { name: "Erneut versuchen" }).isVisible().catch(() => false), `${label}: Knopf „Erneut versuchen“`);
    if (nav) ok(await crash.getByRole("link", { name: /CVEs/ }).first().isVisible().catch(() => false), `${label}: Navigation bleibt nutzbar`);
    const docTitle = await crash.title();
    ok(/patchwatch/.test(docTitle), `${label}: Seitentitel „${docTitle}“`);
    await crash.close();
  }

  // Eigene WebSocket-Verbindung in einem zweiten Tab (ohne App-Skripte, wird nicht neu geladen): sammelt Live-Ereignisse
  // über den ganzen Ausfall.
  const probe = await ctx.newPage();
  await probe.goto(`${base}/icon.svg`);
  await probe.evaluate(() => {
    const w = window;
    w.__pwLive = [];
    const ws = new WebSocket(`${location.origin.replace(/^http/, "ws")}/api/v1/live`);
    ws.onmessage = (e) => w.__pwLive.push({ t: Date.now(), data: String(e.data) });
    ws.onclose = () => w.__pwLive.push({ t: Date.now(), data: "__closed" });
  });
  // „Daten jetzt abrufen“ für einen Host: report_requested per pg_notify -> LISTEN -> WebSocket (ein Feed-Abruf ginge nicht,
  // der Mindestabstand zwischen manuellen Abrufen überspringt ihn).
  // Je Aufruf ein anderer Host: die Anforderung ist je Host zeitlich begrenzt (429).
  const hostIds = ((await call("GET", "/api/v1/hosts")).json ?? []).map((h) => h.id);
  async function liveEventArrives(label, hostId) {
    await probe.waitForFunction(() => window.__pwLive !== undefined);
    const t0 = Date.now();
    const req = await call("POST", `/api/v1/hosts/${hostId}/request-report`);
    let got = false;
    for (let i = 0; i < 40 && !got; i++) {
      const msgs = await probe.evaluate(() => window.__pwLive ?? []);
      got = msgs.some((m) => m.t >= t0 && m.data.includes('"report_requested"'));
      if (!got) await sleep(500);
    }
    const msgs = await probe.evaluate(() => window.__pwLive ?? []);
    const types = [...new Set(msgs.map((m) => (m.data.match(/"type":"([a-z_]+)"/) ?? [, m.data])[1]))].join(", ");
    ok(got, `${label}: Report-Anforderung (${req.status}) kommt per WebSocket an (Ereignisse bisher: ${types || "keine"})`);
  }
  await sleep(500);
  await liveEventArrives("LISTEN/NOTIFY vor dem Ausfall", hostIds[0]);

  // ---- Ausfall ----
  docker("stop", container);
  stopped = true;
  const tStop = Date.now();
  console.log(`     ${container} gestoppt`);

  const hosts = await call("GET", "/api/v1/hosts");
  ok(hosts.status === 503, `Ausfall: GET /hosts -> ${hosts.status} (erwartet 503) in ${hosts.ms} ms`);
  ok(hosts.ms < 7000, `Ausfall: Antwort in ${hosts.ms} ms (< 7 s)`);
  ok(typeof hosts.json?.error === "string" && /Datenbank/.test(hosts.json.error) && !INTERNAL.test(hosts.text),
    `Ausfall: deutscher Text ohne interne Details: ${JSON.stringify(hosts.json?.error ?? hosts.text.slice(0, 80))}`);
  ok(Number(hosts.headers.get("retry-after")) > 0, `Ausfall: Retry-After ${hosts.headers.get("retry-after")}`);
  const lg = await call("POST", "/api/v1/auth/login", { username: user, password: pw });
  ok(lg.status === 503, `Ausfall: POST /auth/login -> ${lg.status} (erwartet 503, nicht 401/500)`);
  const rd = await call("GET", "/readyz");
  ok(rd.status === 503, `Ausfall: /readyz -> ${rd.status}`);

  // Neu laden während des Ausfalls: keine Umleitung zur Anmeldung, keine leere Seite, verständliche Meldung.
  await page.reload();
  const alert = page.getByRole("alert").filter({ hasText: /Datenbank|nicht erreichbar/ }).first();
  const shown = await alert.waitFor({ timeout: 15_000 }).then(() => true, () => false);
  const url1 = new URL(page.url()).pathname;
  const body1 = (await page.locator("body").innerText()).trim();
  ok(!url1.startsWith("/login"), `UI im Ausfall: bleibt auf ${url1} (keine Umleitung zur Anmeldung)`);
  ok(shown, `UI im Ausfall: Fehlermeldung sichtbar: ${JSON.stringify(shown ? (await alert.innerText()).slice(0, 120) : body1.slice(0, 120))}`);
  ok(body1.length > 20 && !INTERNAL.test(body1), "UI im Ausfall: keine leere Seite, keine internen Details");
  const retry = page.getByRole("button", { name: "Erneut versuchen" });
  ok(await retry.isVisible().catch(() => false), "UI im Ausfall: Knopf „Erneut versuchen“ sichtbar");
  // Erneut versuchen, solange die Datenbank fehlt: bleibt im Fehlerzustand, keine Anmeldeseite.
  if (await retry.isVisible().catch(() => false)) {
    await retry.click();
    await sleep(1500);
    await alert.waitFor({ timeout: 15_000 }).catch(() => {});
    ok(!new URL(page.url()).pathname.startsWith("/login") && (await alert.isVisible()), "UI im Ausfall: „Erneut versuchen“ ohne Datenbank bleibt im Fehlerzustand");
  }

  // ---- Erholung ----
  const rest = outageSecs * 1000 - (Date.now() - tStop);
  if (rest > 0) await sleep(rest);
  docker("start", container);
  stopped = false;
  const tStart = Date.now();
  console.log(`     ${container} nach ${Math.round((tStart - tStop) / 1000)} s wieder gestartet`);
  const readyAfter = await waitReady(90);
  ok(readyAfter !== null, `Erholung: /readyz 200 nach ${readyAfter?.toFixed(1)} s`);
  if (pidFile) {
    const pidAfter = serverPid();
    ok(pidBefore && pidBefore === pidAfter && existsSync(`/proc/${pidAfter}`), `Erholung ohne Neustart (Server-PID ${pidBefore} -> ${pidAfter})`);
  }
  const me = await call("GET", "/api/v1/auth/me");
  ok(me.status === 200, `Erholung: bisherige Sitzung gilt (GET /auth/me -> ${me.status})`);
  const after = await counts();
  ok(after.hosts === before.hosts && after.cves === before.cves, `Erholung: ${after.hosts} Hosts, ${after.cves} CVEs (vorher ${before.hosts}/${before.cves})`);

  // UI: "Erneut versuchen" (oder Neuladen) bringt die Seite zurück, ohne Anmeldung.
  if (await retry.isVisible().catch(() => false)) await retry.click();
  else await page.reload();
  const table = await page.getByRole("table").first().waitFor({ timeout: 20_000 }).then(() => true, () => false);
  ok(table && !new URL(page.url()).pathname.startsWith("/login"), "UI nach Erholung: Host-Liste wieder da, weiter angemeldet");
  const live = await liveIndicator.filter({ hasText: /^Live$/ }).waitFor({ timeout: 45_000 }).then(() => true, () => false);
  ok(live, "UI nach Erholung: Live-Anzeige wieder „Live“");

  // LISTEN/NOTIFY: das Ereignis muss auch nach der Erholung ankommen (Live-Listener hat neu verbunden und LISTEN erneuert).
  await liveEventArrives("LISTEN/NOTIFY nach der Erholung", hostIds[1] ?? hostIds[0]);
  const closed = (await probe.evaluate(() => window.__pwLive ?? [])).some((m) => m.data === "__closed");
  console.log(`     WebSocket des zweiten Tabs: ${closed ? "zwischendurch getrennt" : "durchgehend offen"}`);
  ok(pageErrors.length === 0, `keine Skriptfehler im Browser${pageErrors.length ? ": " + pageErrors.slice(0, 3).join(" | ") : ""}`);
} catch (e) {
  ok(false, `Abbruch: ${e.message}`);
} finally {
  // Den Container nie gestoppt zurücklassen.
  if (stopped || !pgRunning()) {
    try { docker("start", container); console.log(`     ${container} wieder gestartet (Aufräumen)`); } catch (e) { console.error(`Container ${container} konnte nicht gestartet werden: ${e.message}`); process.exitCode = 1; }
  }
  await browser.close();
}
