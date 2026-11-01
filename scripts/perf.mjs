// Messung der UI-Performance mit Playwright gegen einen laufenden Stack.
//   PW_MODULE=… PW_CHROME=… PW_PASSWORD=… PW_BASE=http://127.0.0.1:3200 [CPU=4] node scripts/perf.mjs > perf.json
// Gemessen werden je Seite (Hosts, CVEs, Agents, Einstellungen): Kaltstart (goto), Seitenwechsel per Klick (Client-Navigation),
// API-Anfragen/Bytes, JavaScript-Bytes, Long Tasks (> 50 ms) und die Reaktionszeit typischer Aktionen.
import { createRequire } from "node:module";
const { chromium } = createRequire(import.meta.url)(process.env.PW_MODULE ?? "playwright");
const base = (process.env.PW_BASE ?? "http://127.0.0.1:3200").replace(/\/$/, "");
const cpu = Number(process.env.CPU ?? 1);
const REPS = Number(process.env.REPS ?? 3);
const med = (a) => a.length ? [...a].sort((x, y) => x - y)[Math.floor(a.length / 2)] : null;
const r1 = (n) => (n == null ? null : Math.round(n * 10) / 10);

const browser = await chromium.launch({ executablePath: process.env.PW_CHROME, args: ["--no-sandbox"] });
const login = await browser.newContext({ viewport: { width: 1440, height: 900 } });
{
  const p = await login.newPage();
  await p.goto(`${base}/login`);
  await p.getByLabel("Benutzername").fill("admin");
  await p.getByLabel("Passwort").fill(process.env.PW_PASSWORD);
  await p.getByRole("button", { name: "Anmelden" }).click();
  await p.waitForURL((u) => !u.pathname.startsWith("/login"));
}
const state = await login.storageState();

const PAGES = [
  ["Hosts", "/"],
  ["CVEs", "/cves"],
  ["Agents", "/agents"],
  ["Einstellungen", "/settings"],
];
// "nutzbar": Inhalt da, kein Skeleton mehr.
const USABLE = `(() => { const m = document.querySelector("main") ?? document.body; return !m.querySelector('[aria-busy="true"]') && (m.querySelector("tbody tr, input, select") !== null); })()`;

async function newPage() {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, storageState: state });
  const page = await ctx.newPage();
  const cdp = await ctx.newCDPSession(page);
  if (cpu > 1) await cdp.send("Emulation.setCPUThrottlingRate", { rate: cpu });
  await cdp.send("Network.enable");
  const net = { api: 0, apiBytes: 0, js: 0, jsBytes: 0, other: 0, otherBytes: 0, apiList: [] };
  const types = new Map();
  cdp.on("Network.responseReceived", (e) => types.set(e.requestId, { url: e.response.url, type: e.type }));
  cdp.on("Network.loadingFinished", (e) => {
    const t = types.get(e.requestId);
    if (!t) return;
    const bytes = e.encodedDataLength;
    if (t.url.includes("/api/v1/")) { net.api++; net.apiBytes += bytes; net.apiList.push(`${t.url.replace(/^.*\/api\/v1/, "")} ${bytes}`); }
    else if (t.type === "Script") { net.js++; net.jsBytes += bytes; }
    else { net.other++; net.otherBytes += bytes; }
  });
  // NOVT=1: Seitenübergang ohne View Transitions messen (Vergleich, ob die Animation die Navigation verzögert).
  if (process.env.NOVT) await page.addInitScript(() => { document.startViewTransition = undefined; });
  await page.addInitScript(() => {
    window.__long = [];
    window.__lcp = 0;
    new PerformanceObserver((l) => { for (const e of l.getEntries()) window.__long.push(Math.round(e.duration)); }).observe({ type: "longtask", buffered: true });
    new PerformanceObserver((l) => { for (const e of l.getEntries()) window.__lcp = e.startTime; }).observe({ type: "largest-contentful-paint", buffered: true });
  });
  return { ctx, page, net };
}

const out = { base, cpu, pages: {} };
for (const [name, path] of process.env.SKIP_COLD ? [] : PAGES) {
  const cold = [];
  for (let i = 0; i < REPS; i++) {
    const { ctx, page, net } = await newPage();
    const t0 = Date.now();
    await page.goto(base + path, { waitUntil: "commit" });
    await page.waitForFunction(`document.querySelector("main") !== null`, null, { timeout: 60000 });
    const tFirst = Date.now() - t0;
    await page.waitForFunction(USABLE, null, { timeout: 60000, polling: 16 });
    const tUsable = Date.now() - t0;
    await page.waitForTimeout(800);
    const m = await page.evaluate(() => ({
      fcp: performance.getEntriesByName("first-contentful-paint")[0]?.startTime ?? 0,
      lcp: window.__lcp, long: window.__long,
      ttfb: performance.getEntriesByType("navigation")[0].responseStart,
    }));
    cold.push({ tFirst, tUsable, ...m, ...net });
    await ctx.close();
  }
  const pick = (k) => med(cold.map((c) => c[k]));
  const last = cold[cold.length - 1];
  out.pages[name] = {
    ttfb: r1(pick("ttfb")), fcp: r1(pick("fcp")), lcp: r1(pick("lcp")), firstMain: pick("tFirst"), usable: pick("tUsable"),
    apiRequests: last.api, apiKB: r1(last.apiBytes / 1024), jsRequests: last.js, jsKB: r1(last.jsBytes / 1024),
    longTasks: last.long.filter((d) => d > 50).length, longTaskMax: Math.max(0, ...last.long), apiList: last.apiList,
  };
}

// Seitenwechsel im geladenen Client (Sidebar-Klick): Reaktion = URL + Überschrift da, Daten = nutzbar.
{
  const { ctx, page, net } = await newPage();
  await page.goto(base + "/", { waitUntil: "commit" });
  await page.waitForFunction(USABLE, null, { timeout: 60000 });
  // Warmlauf: jede Seite einmal besuchen (Dev: Kompilierung, Prod: Chunks laden).
  for (const [n] of PAGES.slice(1).concat([PAGES[0]])) { await page.getByRole("link", { name: n === "Hosts" ? "Hosts" : n, exact: true }).first().click(); await page.waitForFunction(USABLE, null, { timeout: 60000 }); }
  const nav = {};
  for (let rep = 0; rep < REPS; rep++) {
    for (const [n, p] of PAGES.slice(1).concat([PAGES[0]])) {
      await page.evaluate(() => { window.__t0 = 0; document.addEventListener("pointerdown", () => (window.__t0 = performance.now()), { capture: true, once: true }); });
      const apiBefore = net.api;
      await page.getByRole("link", { name: n, exact: true }).first().click();
      const r = await page.evaluate(([p, usable]) => new Promise((res) => {
        let tNav = 0;
        const tick = () => {
          const now = performance.now();
          if (!tNav && location.pathname === p && document.querySelector("main h1, main h2")) tNav = now;
          if (tNav && eval(usable)) return res({ nav: tNav - window.__t0, data: now - window.__t0 });
          if (now - window.__t0 > 20000) return res({ nav: tNav - window.__t0, data: -1 });
          requestAnimationFrame(tick);
        };
        tick();
      }), [p, USABLE]);
      (nav[n] ??= { nav: [], data: [], api: [] });
      nav[n].nav.push(r.nav); nav[n].data.push(r.data); nav[n].api.push(net.api - apiBefore);
      await page.waitForTimeout(400);
    }
  }
  out.navigation = Object.fromEntries(Object.entries(nav).map(([k, v]) => [k, { reactMs: r1(med(v.nav)), dataMs: r1(med(v.data)), apiRequests: med(v.api) }]));

  // Aktionen: Klick bis sichtbare Reaktion.
  const act = {};
  const timeIt = async (label, prep, fire, cond, arg) => {
    const rs = [];
    for (let i = 0; i < REPS; i++) {
      await prep?.();
      await page.evaluate(() => { window.__t0 = 0; document.addEventListener("pointerdown", () => (window.__t0 = performance.now()), { capture: true, once: true }); document.addEventListener("keydown", () => (window.__t0 = performance.now()), { capture: true, once: true }); });
      await fire();
      rs.push(await page.evaluate(([c, a]) => new Promise((res) => { const f = new Function("a", `return (${c})`); const tick = () => { const now = performance.now(); if (f(a)) return res(now - window.__t0); if (now - window.__t0 > 10000) return res(-1); requestAnimationFrame(tick); }; tick(); }), [cond, arg]));
      await page.waitForTimeout(300);
    }
    act[label] = r1(med(rs));
  };
  await page.goto(base + "/cves", { waitUntil: "commit" });
  await page.waitForFunction(USABLE, null, { timeout: 60000 });
  const star = () => page.locator("tbody .star-btn").nth(5);
  // Der Stern-Test braucht den Ausgangszustand; einfacher: Label-Wechsel messen.
  {
    const rs = [];
    for (let i = 0; i < REPS; i++) {
      const before = await star().getAttribute("aria-label");
      await page.evaluate(() => { window.__t0 = 0; document.addEventListener("pointerdown", () => (window.__t0 = performance.now()), { capture: true, once: true }); });
      await star().click();
      rs.push(await page.evaluate((b) => new Promise((res) => { const tick = () => { const now = performance.now(); if (document.querySelectorAll("tbody .star-btn")[5]?.getAttribute("aria-label") !== b) return res(now - window.__t0); if (now - window.__t0 > 5000) return res(-1); requestAnimationFrame(tick); }; tick(); }), before));
      await page.waitForTimeout(600);
    }
    act["Stern (Klick bis Zustand)"] = r1(med(rs));
  }
  // Filter: Tippen bis die Tabelle neue Zeilen zeigt (inkl. Debounce und Abruf).
  {
    const rs = [];
    for (let i = 0; i < REPS; i++) {
      await page.getByPlaceholder("CVE-ID oder Text").fill("");
      await page.waitForFunction(() => document.querySelectorAll("tr:has(.star-btn)").length > 5, null, { timeout: 20000 });
      await page.waitForTimeout(500);
      const first = await page.locator("tr:has(.star-btn)").first().innerText();
      // Zieht eine CVE aus der Mitte der Liste: sie ist nicht die erste Zeile, die Liste muss sich also ändern.
      const target = (await page.locator("tr:has(.star-btn) a.mono").nth(20).innerText()).trim();
      await page.evaluate(() => { window.__t0 = 0; document.addEventListener("keydown", () => (window.__t0 = performance.now()), { capture: true, once: true }); });
      await page.getByPlaceholder("CVE-ID oder Text").pressSequentially(target, { delay: 0 });
      rs.push(await page.evaluate((f) => new Promise((res) => { const tick = () => { const now = performance.now(); const r = document.querySelector("tr:has(.star-btn)"); if (r && r.innerText !== f && !document.querySelector('main [aria-busy="true"]')) return res(now - window.__t0); if (now - window.__t0 > 8000) return res(-1); requestAnimationFrame(tick); }; tick(); }), first));
    }
    act["Filter (Tippen bis neue Liste)"] = r1(med(rs));
  }
  await page.goto(base + "/agents", { waitUntil: "commit" });
  await page.waitForFunction(USABLE, null, { timeout: 60000 });
  await timeIt("Dialog öffnen (Agents)", async () => { await page.keyboard.press("Escape"); }, () => page.getByRole("button", { name: "Agent hinzufügen" }).click(), `document.querySelector("dialog[open]") !== null`);
  out.actions = act;
  out.longTasksSession = await page.evaluate(() => window.__long.filter((d) => d > 50));
  await ctx.close();
}
await browser.close();
console.log(JSON.stringify(out, null, 1));
