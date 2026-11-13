// E2E: Die Quellen-Tabelle bleibt während eines (simulierten) langen Abrufs ruhig: x-Position und Breite jeder Spalte,
// der Tabelle, des Inhaltsbereichs und der Seite (clientWidth) ändern sich nicht, auch nicht bei Start und Ende.
// Der Lauf wird per page.route nachgestellt (Dauer RUN_SECS, Standard 20); der Server bekommt keine Schreibzugriffe.
//   PW_MODULE=… PW_CHROME=… PW_PWFILE=<Datei> AXE_JS=… [RUN_SECS=20] [SIZES=390,768,1440,1920] [MOTION=reduce,no-preference]
//   [ACTIONS=one,all] [PW_SHOTS=<Ordner>] [REPORT=1 gibt die größte Verschiebung je Messgröße aus] node scripts/e2e-feeds-stable.mjs
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
const { chromium } = createRequire(import.meta.url)(process.env.PW_MODULE);
const pw = readFileSync(process.env.PW_PWFILE, "utf8").trim();
const axeSrc = readFileSync(process.env.AXE_JS, "utf8");
const base = process.env.PW_BASE ?? "http://127.0.0.1:3100";
const RUN = Number(process.env.RUN_SECS ?? 20) * 1000;
const sizes = (process.env.SIZES ?? "390,768,1440,1920").split(",").map(Number);
const motions = (process.env.MOTION ?? "reduce,no-preference").split(",");
const actions = (process.env.ACTIONS ?? "one,all").split(",");
const schemes = (process.env.SCHEMES ?? "light").split(",");
const TOL = 0.5;
const ok = (c, m) => { console.log(c ? "OK  " : "FAIL", m); if (!c) process.exitCode = 1; };
const json = (status, body) => ({ status, contentType: "application/json", body: JSON.stringify(body) });
const iso = (ms) => new Date(Date.now() + ms).toISOString();

const feed = (o) => ({ source: "debian", type: "debian", label: "Debian", ecosystem: null, takes_ecosystem: false, kind: "builtin", enabled: true, configured: true, enrich_only: false, takes_secret: false, takes_base_url: false, secret_set: false, base_url: null, interval_minutes: 60, state: "ok", healthy: true, last_attempt_at: iso(-60e3), last_success_at: iso(-60e3), stale_since: null, last_error: null, last_error_at: null, consecutive_failures: 0, failed_runs: 0, next_attempt_at: iso(59 * 60e3), error_text: null, backfill: null, bulk: null, ...o });
const FEEDS = [feed(), feed({ source: "ubuntu", type: "ubuntu", label: "Ubuntu", interval_minutes: 1440 }), feed({ source: "nvd", type: "nvd", label: "NVD", kind: "custom", enrich_only: true, interval_minutes: 120 })];

// Zustand des simulierten Laufs (Quelle ubuntu): Verbinden 0–1 s, Herunterladen bis 70 %, Auswerten, Speichern, Prüfen.
let started = null;
function run() {
  if (started === null) return null;
  const t = Date.now() - started;
  const f = RUN, phase = t < 1000 ? "connect" : t < f * 0.7 ? "download" : t < f * 0.85 ? "parse" : t < f * 0.95 ? "store" : t < f ? "evaluate" : "done";
  const done = t >= f;
  return { id: 900, source: "ubuntu", trigger: "manual", started_by: "admin", status: done ? "ok" : "running", phase, created_at: new Date(started).toISOString(), started_at: new Date(started).toISOString(), finished_at: done ? new Date(started + f).toISOString() : null, bytes: Math.min(14_900_000, Math.round((t / f) * 14_900_000)), items: done ? 4400 : null, hosts: done ? 5 : null, error: null, phases: { connect: 300, download: Math.max(0, Math.min(t, f * 0.7) - 1000) } };
}

// Im Seitenkontext alle 250 ms messen; Rückgabe der Proben nach `ms`.
const SAMPLER = (ms) => new Promise((resolve) => {
  const out = [];
  const t0 = performance.now();
  // x relativ zur Seite inklusive Scrollversatz des Tabellen-Wrappers: Scrollen (z. B. durch den Klick) ist keine Verschiebung.
  const rect = (e) => { const r = e.getBoundingClientRect(); const sc = e.closest('[class*="overflow-x-auto"]'); return [r.left + scrollX + (sc ? sc.scrollLeft : 0), r.width]; };
  const tick = () => {
    const table = document.querySelector('table[aria-labelledby], table.tbl');
    const cells = table ? [...table.querySelectorAll("tbody > tr:not(.run-row)")].flatMap((tr, i) => [...tr.children].map((c, j) => [`${i}.${j}`, ...rect(c)])) : [];
    const heads = table ? [...table.querySelectorAll("thead th")].map((c, j) => [`h${j}`, ...rect(c)]) : [];
    const main = document.getElementById("main");
    out.push({ t: Math.round(performance.now() - t0), cw: document.documentElement.clientWidth, iw: innerWidth, sw: document.documentElement.scrollWidth, main: main ? rect(main) : null, table: table ? rect(table) : null, cols: [...heads, ...cells] });
    if (performance.now() - t0 < ms) setTimeout(tick, 250); else resolve(out);
  };
  tick();
});

function deviations(samples) {
  const worst = { clientWidth: 0, innerWidth: 0, pageScrollWidth: 0, mainX: 0, mainW: 0, tableX: 0, tableW: 0, colX: 0, colW: 0 };
  const first = samples[0];
  const span = (k, v) => { worst[k] = Math.max(worst[k], v); };
  const fc = new Map(first.cols.map(([k, x, w]) => [k, [x, w]]));
  for (const s of samples) {
    span("clientWidth", Math.abs(s.cw - first.cw)); span("innerWidth", Math.abs(s.iw - first.iw)); span("pageScrollWidth", Math.abs(s.sw - first.sw));
    if (first.main && s.main) { span("mainX", Math.abs(s.main[0] - first.main[0])); span("mainW", Math.abs(s.main[1] - first.main[1])); }
    if (first.table && s.table) { span("tableX", Math.abs(s.table[0] - first.table[0])); span("tableW", Math.abs(s.table[1] - first.table[1])); }
    for (const [k, x, w] of s.cols) { const f = fc.get(k); if (!f) continue; span("colX", Math.abs(x - f[0])); span("colW", Math.abs(w - f[1])); }
  }
  return worst;
}

const browser = await chromium.launch({ executablePath: process.env.PW_CHROME, args: ["--no-sandbox"] });
try {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await ctx.newPage();
  await page.goto(`${base}/login`);
  await page.getByLabel("Benutzername").fill("admin");
  await page.getByLabel("Passwort").fill(pw);
  await page.getByRole("button", { name: "Anmelden" }).click();
  await page.waitForURL((u) => !u.pathname.startsWith("/login"));
  await page.route(/\/api\/v1\/feeds$/, (r) => (r.request().method() === "GET" ? r.fulfill(json(200, FEEDS)) : r.continue()));
  await page.route("**/api/v1/feeds/runs**", (r) => { const x = run(); return r.fulfill(json(200, { runs: x ? [x] : [] })); });
  await page.route("**/api/v1/feeds/ubuntu/run", (r) => { started = Date.now(); return r.fulfill(json(202, { run: run() })); });
  await page.route("**/api/v1/feeds/refresh", (r) => { started = Date.now(); return r.fulfill(json(202, { runs: [{ run_id: 900 }], running: [], skipped: [] })); });

  for (const scheme of schemes) for (const motion of motions) for (const w of sizes) for (const action of actions) {
    const label = `${w}px ${scheme} ${motion === "reduce" ? "reduziert" : "Bewegung"} ${action === "one" ? "Jetzt abrufen" : "Alle abrufen"}`;
    started = null;
    await page.emulateMedia({ colorScheme: scheme, reducedMotion: motion });
    await page.setViewportSize({ width: w, height: 900 });
    await page.goto(`${base}/cves`);
    await page.getByRole("table", { name: "Zustand der CVE-Quellen" }).waitFor();
    await page.waitForTimeout(600);
    const sampling = page.evaluate(SAMPLER, RUN + 6000);
    await page.waitForTimeout(1000); // Ruhephase vor dem Start
    if (action === "one") await page.getByRole("button", { name: "Ubuntu jetzt abrufen" }).click();
    else await page.getByRole("button", { name: "Alle abrufen" }).click();
    if (process.env.PW_SHOTS && w === 1440 && action === "one" && motion === "reduce") { await page.waitForTimeout(RUN / 2); await page.screenshot({ path: `${process.env.PW_SHOTS}/stable-${scheme}-mid.png` }); }
    const samples = await sampling;
    const d = deviations(samples);
    const lastTexts = await page.getByRole("table", { name: "Zustand der CVE-Quellen" }).innerText();
    ok(/Abgeschlossen|Fertig/.test(lastTexts), `${label}: der Lauf wurde bis zum Ende angezeigt`);
    if (process.env.REPORT) {
      const f0 = new Map(samples[0].cols.map(([k, x, ww]) => [k, [x, ww]]));
      const per = new Map();
      for (const s of samples) for (const [k, x, ww] of s.cols) { const f = f0.get(k); if (!f) continue; const e = per.get(k) ?? { dx: 0, dw: 0, at: 0 }; const dw = Math.abs(ww - f[1]); if (dw > e.dw) { e.dw = dw; e.at = s.t; } e.dx = Math.max(e.dx, Math.abs(x - f[0])); per.set(k, e); }
      console.log("SPALTEN", [...per].filter(([, e]) => e.dw > TOL || e.dx > TOL).slice(0, 12).map(([k, e]) => `${k}: dx ${e.dx.toFixed(0)} dw ${e.dw.toFixed(0)} @${e.at}ms`).join(" | "));
      console.log("BREITEN", samples.filter((_, i) => i % 8 === 0).map((s) => `${s.t}:` + s.cols.filter(([k]) => k.startsWith("h")).map(([, , ww]) => Math.round(ww)).join("/")).join("  "));
    }
    if (process.env.REPORT) console.log(`MESS ${label}:`, JSON.stringify(d), `Proben ${samples.length}`);
    for (const [k, v] of Object.entries(d)) ok(v <= TOL, `${label}: ${k} ändert sich um höchstens ${TOL} px (größte Abweichung ${v.toFixed(2)})`);
  }
  // axe auf der Seite mit abgeschlossenem Lauf
  await page.evaluate(axeSrc);
  const v = await page.evaluate(() => axe.run(document, { runOnly: ["wcag2a", "wcag2aa", "wcag21aa", "best-practice"] }).then((r) => r.violations.map((x) => `${x.id}: ${x.nodes.length}`)));
  ok(v.length === 0, `axe ${v.join(", ") || "keine Verstöße"}`);
} finally {
  await browser.close();
}
