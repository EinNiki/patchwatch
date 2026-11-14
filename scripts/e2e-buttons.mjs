// E2E: gleich große Knöpfe in Aktionsreihen (CVE-Quellen: Zeile und Kopfzeile) sowie CVE-Werkzeugleiste und Ablauf-Knöpfe (RunStepper): 32 px, mobil 44 px. Prüft Breite/Höhe in Ruhe, „Läuft“, deaktiviert, Fokus, Hover,
// kein Sprung der Nachbarzellen beim Wechsel zu „Läuft“, 44 px mobil, axe. Quellen und Läufe per page.route nachgestellt; keine Schreibzugriffe.
//   PW_MODULE=… PW_CHROME=… PW_PWFILE=<Datei mit Admin-Passwort> AXE_JS=… node scripts/e2e-buttons.mjs
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
const { chromium } = createRequire(import.meta.url)(process.env.PW_MODULE);
const pw = readFileSync(process.env.PW_PWFILE, "utf8").trim();
const axe = readFileSync(process.env.AXE_JS, "utf8");
const base = process.env.PW_BASE ?? "http://127.0.0.1:3100";
const ok = (c, m) => { console.log(c ? "OK  " : "FAIL", m); if (!c) process.exitCode = 1; };
const json = (status, body) => ({ status, contentType: "application/json", body: JSON.stringify(body) });
const iso = (min) => new Date(Date.now() + min * 60_000).toISOString();
const feed = (o) => ({ source: "debian", type: "debian", label: "Debian", ecosystem: null, takes_ecosystem: false, kind: "builtin", enabled: true, configured: true, enrich_only: false, takes_secret: false, takes_base_url: false, secret_set: false, base_url: null, interval_minutes: 60, state: "ok", healthy: true, last_attempt_at: iso(-1), last_success_at: iso(-1), stale_since: null, last_error: null, last_error_at: null, consecutive_failures: 0, failed_runs: 0, next_attempt_at: iso(59), error_text: null, backfill: null, bulk: null, ...o });
const mkRun = (o) => ({ id: 1, source: "", trigger: "manual", started_by: "admin", status: "running", phase: "connect", created_at: new Date().toISOString(), started_at: new Date().toISOString(), finished_at: null, bytes: 0, items: null, hosts: null, error: null, phases: {}, ...o });
const FEEDS = [
  feed(),
  feed({ source: "ubuntu", type: "ubuntu", label: "Ubuntu", state: "incomplete", stale_since: iso(-90), last_error: "HTTP 503", last_error_at: iso(-1), consecutive_failures: 4, failed_runs: 4, error_text: "Ubuntu meldet 503, nächster Versuch in 12 Minuten", next_attempt_at: iso(12) }),
  feed({ source: "osv", type: "osv", label: "Aus", enabled: false, state: "disabled", next_attempt_at: null }),
];

const browser = await chromium.launch({ executablePath: process.env.PW_CHROME, args: ["--no-sandbox"] });
const state = { runs: [] };
try {
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 }, reducedMotion: "reduce" });
  const page = await ctx.newPage();
  await page.addInitScript(() => { try { localStorage.setItem("pw-feeds-manage", "1"); } catch {} });
  await page.goto(`${base}/login`);
  await page.getByLabel("Benutzername").fill("admin");
  await page.getByLabel("Passwort").fill(pw);
  await page.getByRole("button", { name: "Anmelden", exact: true }).click();
  await page.waitForURL((u) => !u.pathname.startsWith("/login"));
  await page.route(/\/api\/v1\/feeds$/, (r) => (r.request().method() === "GET" ? r.fulfill(json(200, FEEDS)) : r.continue()));
  await page.route("**/api/v1/feeds/runs**", (r) => r.fulfill(json(200, { runs: state.runs })));

  // Geometrie aller Knöpfe einer Quellenzeile und der Nachbarzellen.
  const geo = (src) => page.evaluate((label) => {
    const tr = [...document.querySelectorAll("table#feeds-table tbody tr, table.tbl tbody tr")].find((r) => r.querySelector("td")?.textContent.trim().startsWith(label));
    const box = (e) => { const r = e.getBoundingClientRect(); return [r.x, r.y, r.width, r.height].map((n) => Math.round(n * 10) / 10); };
    const btns = [...tr.querySelectorAll(".feed-actions button")].map(box);
    const cells = [...tr.querySelectorAll("td")].filter((c) => !c.querySelector(".feed-actions")).map(box);
    return { btns, cells, dis: [...tr.querySelectorAll(".feed-actions button")].map((b) => b.disabled) };
  }, src);
  const same = (arr, i) => arr.every((b) => Math.abs(b[i] - arr[0][i]) <= 0.5);
  const axeRun = async (tag) => {
    await page.evaluate(axe);
    const res = await page.evaluate(() => globalThis.axe.run(document, { runOnly: ["wcag2a", "wcag2aa", "wcag22aa", "best-practice"] }));
    const bad = res.violations.filter((v) => !["region", "landmark-one-main", "page-has-heading-one"].includes(v.id));
    ok(bad.length === 0, `${tag}: axe ${bad.map((v) => v.id + ":" + v.nodes[0]?.target).join(", ")}`);
  };

  for (const scheme of ["light", "dark"]) {
    for (const w of [390, 768, 1024, 1280, 1440, 1920, 2560]) {
      const tag = `${w}px ${scheme}`;
      await page.emulateMedia({ colorScheme: scheme, reducedMotion: "reduce" });
      await page.setViewportSize({ width: w, height: 900 });
      state.runs = [];
      await page.goto(`${base}/cves`);
      await page.locator(".feed-actions").first().waitFor();
      await page.waitForTimeout(700);
      const want = w < 768 ? 44 : 32;
      const rest = await geo("Debian");
      ok(rest.btns.length === 4, `${tag}: vier Knöpfe je Zeile`);
      ok(same(rest.btns, 2) && same(rest.btns, 3), `${tag}: Ruhe: alle vier gleich groß ${JSON.stringify(rest.btns.map((b) => [b[2], b[3]]))}`);
      ok(Math.abs(rest.btns[0][3] - want) <= 0.5, `${tag}: Höhe ${want} px (${rest.btns[0][3]})`);
      // Deaktiviert: Zeile „Aus“ (abgeschaltet) – Größe gleich wie die anderen Zeilen.
      const off = await geo("Aus");
      ok(off.dis[0] === true && Math.abs(off.btns[0][2] - rest.btns[0][2]) <= 0.5 && Math.abs(off.btns[0][3] - rest.btns[0][3]) <= 0.5, `${tag}: deaktiviert gleich groß`);
      // Hover und Fokus ändern die Größe nicht.
      const b0 = page.locator("tr", { hasText: "Debian" }).first().locator(".feed-actions button").nth(1);
      await b0.hover();
      let g = await geo("Debian");
      ok(same(g.btns, 2) && Math.abs(g.btns[1][2] - rest.btns[1][2]) <= 0.5 && Math.abs(g.btns[1][3] - rest.btns[1][3]) <= 0.5, `${tag}: Hover gleich groß`);
      await b0.focus();
      g = await geo("Debian");
      ok(Math.abs(g.btns[1][2] - rest.btns[1][2]) <= 0.5 && Math.abs(g.btns[1][3] - rest.btns[1][3]) <= 0.5, `${tag}: Fokus gleich groß`);
      // Kopfzeile: drei gleich große Knöpfe.
      const head = await page.evaluate(() => [...document.querySelectorAll(".src-actions > button")].map((b) => { const r = b.getBoundingClientRect(); return [r.width, r.height]; }));
      ok(head.length === 3 && head.every((h) => Math.abs(h[0] - head[0][0]) <= 0.5 && Math.abs(h[1] - head[0][1]) <= 0.5) || w < 640, `${tag}: Kopfzeile gleich groß ${JSON.stringify(head)}`);
      ok(head.every((h) => Math.abs(h[1] - (w < 768 ? 44 : 32)) <= 0.5), `${tag}: Kopfzeile Höhe`);
      // Läuft: gleiche Größe, Nachbarzellen unverändert, Text „Läuft“ (Textmodus), Tooltip mit Fortschritt.
      state.runs = [mkRun({ id: 7, source: "debian", status: "running", phase: "download" })];
      await page.reload();
      await page.locator(".feed-actions").first().waitFor();
      await page.waitForTimeout(1500);
      const run = await geo("Debian");
      ok(same(run.btns, 2) && same(run.btns, 3), `${tag}: Läuft: alle vier gleich groß`);
      ok(Math.abs(run.btns[0][2] - rest.btns[0][2]) <= 0.5 && Math.abs(run.btns[0][3] - rest.btns[0][3]) <= 0.5, `${tag}: Läuft: Größe wie in Ruhe (${run.btns[0][2]}×${run.btns[0][3]})`);
      const first = page.locator("tr", { hasText: "Debian" }).first().locator(".feed-actions button").first();
      ok((await first.getAttribute("title"))?.startsWith("Abruf läuft"), `${tag}: Tooltip nennt den Fortschritt`);
      ok((await first.getAttribute("aria-busy")) === "true", `${tag}: aria-busy`);
      const txt = (await first.innerText()).trim();
      ok(w < 1024 || txt === "" || txt === "Läuft", `${tag}: Text „Läuft“ oder Symbol (${txt})`);
      // Nachbarzellen (Quelle, Zustand, …): keine Verschiebung > 0,5 px; Zustandsspalte darf den Fortschritt zeigen, daher nur x/Breite.
      const moved = rest.cells.some((c, i) => run.cells[i] && (Math.abs(c[0] - run.cells[i][0]) > 0.5 || Math.abs(c[2] - run.cells[i][2]) > 0.5));
      ok(!moved || w < 1024, `${tag}: Nachbarzellen bleiben stehen`);
      if (w === 1280 || w === 390) await axeRun(tag);
    }
  }

  // ---- Gemeinsame Knopfgröße außerhalb der Quellenzeile: CVE-Werkzeugleiste und Ablauf-Anzeige (RunStepper). ----
  // Gleichrangige Knöpfe 32 px (mobil 44 px) ±0,5 in Ruhe, Hover, Fokus, gedrückt/eingeschaltet; kein Sprung der Nachbarn.
  // Lagen relativ zum ersten Element (Scrollen beim Fokussieren zählt nicht als Sprung).
  const rects = (sel) => page.evaluate((q) => { const l = typeof q === "string" ? [...document.querySelectorAll(q)] : [...document.querySelectorAll("button")].filter((b) => q.includes(b.textContent.trim())); const o = l[0].getBoundingClientRect(); return l.map((e) => { const r = e.getBoundingClientRect(); return [r.x - o.x, r.y - o.y, r.width, r.height]; }); }, sel);
  const near = (a, b) => a.length === b.length && a.every((r, i) => r.every((v, j) => Math.abs(v - b[i][j]) <= 0.5));
  for (const scheme of ["light", "dark"]) {
    for (const w of [390, 1024, 1440]) {
      const tag = `Werkzeugleiste ${w}px ${scheme}`;
      const want = w < 768 ? 44 : 32;
      await page.emulateMedia({ colorScheme: scheme, reducedMotion: "reduce" });
      await page.setViewportSize({ width: w, height: 900 });
      state.runs = [];
      await page.goto(`${base}/cves`);
      await page.locator("#cve-filters").waitFor();
      await page.waitForTimeout(500);
      const bar = "#cve-filters > *";
      const rest = await rects(bar);
      ok(rest.length === 4 && rest.every((r) => Math.abs(r[3] - want) <= 0.5), `${tag}: Suche, Filter, Stern, „CVE beobachten“ ${want} px hoch (${rest.map((r) => r[3])})`);
      const filter = page.locator("#cve-filters button[aria-haspopup]");
      const star = page.getByRole("button", { name: "Nur Watchlist" });
      const add = page.getByRole("button", { name: "CVE beobachten" });
      for (const [name, el] of [["Filter", filter], ["Stern", star], ["CVE beobachten", add]]) {
        await el.hover();
        ok(near(await rects(bar), rest), `${tag}: ${name} Hover, kein Sprung`);
        await page.mouse.move(2, 2);
        await el.focus();
        ok(near(await rects(bar), rest), `${tag}: ${name} Fokus, kein Sprung`);
        await el.blur();
      }
      // Stern gedrückt und eingeschaltet (aria-pressed): Größe und Nachbarn bleiben.
      await star.click();
      await page.waitForTimeout(600);
      ok((await star.getAttribute("aria-pressed")) === "true" && near(await rects(bar), rest), `${tag}: Stern eingeschaltet, keine Größenänderung`);
      await star.click();
      await page.waitForTimeout(600);
      ok(near(await rects(bar), rest), `${tag}: Stern wieder aus, keine Größenänderung`);
      // Deaktiviert: derselbe Knopf mit disabled behält die Größe.
      const dis = await add.evaluate((e) => { const b = e.getBoundingClientRect(); e.disabled = true; const a = e.getBoundingClientRect(); e.disabled = false; return [b.width, b.height, a.width, a.height]; });
      ok(Math.abs(dis[0] - dis[2]) <= 0.5 && Math.abs(dis[1] - dis[3]) <= 0.5, `${tag}: deaktiviert gleich groß`);
      // Filterknopf mit Popover offen: Größe unverändert.
      await filter.click();
      await page.waitForTimeout(300);
      ok(near(await rects(bar), rest), `${tag}: Filter geöffnet, keine Größenänderung`);
      await page.keyboard.press("Escape");

      // RunStepper: „Erneut versuchen“ und „Schließen“ nach einem fehlgeschlagenen Lauf.
      const t2 = `Ablauf-Knöpfe ${w}px ${scheme}`;
      const now = new Date().toISOString();
      state.runs = [mkRun({ id: 9, source: "debian", status: "failed", phase: "download", finished_at: now, error: "HTTP 503" })];
      await page.reload();
      await page.locator(".feed-actions").first().waitFor();
      await page.waitForTimeout(800);
      const retry = page.getByRole("button", { name: "Erneut versuchen" });
      if ((await retry.count()) === 0) {
        const mini = page.locator("tr", { hasText: "Debian" }).first().locator("button[aria-expanded][aria-label^='Abruf-Details']").first();
        if (await mini.count()) await mini.click();
        await page.waitForTimeout(400);
      }
      const rb = await page.locator("button", { hasText: /^(Erneut versuchen|Schließen)$/ }).evaluateAll((l) => l.map((e) => { const r = e.getBoundingClientRect(); return [r.width, r.height]; }));
      ok(rb.length === 2 && rb.every((r) => Math.abs(r[1] - want) <= 0.5), `${t2}: „Erneut versuchen“ und „Schließen“ ${want} px hoch (${JSON.stringify(rb)})`);
      if (rb.length === 2) {
        const q = ["Erneut versuchen", "Schließen"];
        const before = await rects(q);
        await page.getByRole("button", { name: "Schließen", exact: true }).first().hover();
        ok(near(await rects(q), before), `${t2}: Hover, kein Sprung`);
      }
    }
  }
} finally {
  await browser.close();
}
