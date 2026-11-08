// E2E: CVE-Seite (Filter „Betrifft“ als Auswahlfeld, Kennzahlen, Layout ohne leere Flächen, Überlauf).
//   PW_MODULE=… PW_CHROME=… PW_PWFILE=<Datei mit Admin-Passwort> node scripts/e2e-cves.mjs
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
const { chromium } = createRequire(import.meta.url)(process.env.PW_MODULE);
const pw = readFileSync(process.env.PW_PWFILE, "utf8").trim();
const base = process.env.PW_BASE ?? "http://127.0.0.1:3100";
const ok = (c, m) => { console.log(c ? "OK  " : "FAIL", m); if (!c) process.exitCode = 1; };

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const shots = process.env.PW_SHOTS;
const axeSrc = process.env.AXE_JS ? readFileSync(process.env.AXE_JS, "utf8") : null;
// Erzeugte Zeilen: i % 4 == 0 hoch/kritisch, i % 3 == 0 ohne Fix, jede 7. betrifft keinen Host.
const gen = (n) => Array.from({ length: n }, (_, i) => ({
  id: `CVE-2026-${20000 + i}`, description: `Beispiel ${i}: ein Beschreibungstext`, priority: "medium", level: i % 4 === 0 ? 9 : 5, published_at: "2026-10-01T00:00:00Z",
  updated_at: "2026-11-01T00:00:00Z", last_synced_at: "2026-11-01T00:00:00Z", watched: false, note: null, exploited: false,
  hosts_vulnerable: i % 7 === 0 ? 0 : 1 + (i % 8), hosts_fix_pending: 0, hosts_reboot: 0, hosts_unknown: 0,
  affected_hosts: i % 7 === 0 ? [] : Array.from({ length: Math.min(1 + (i % 8), 6) }, (_, k) => `host-${k}`),
  distros: [{ source: "debian", release: "trixie", status: i % 3 === 0 ? "open" : "fixed", package: "linux", fix_version: i % 3 === 0 ? null : "6.12.5-1", updated_at: "2026-11-01T00:00:00Z", mine: true }],
  hidden_releases: 0,
}));
const expected = (rows) => {
  const aff = rows.filter((c) => c.hosts_vulnerable > 0);
  const withFix = aff.filter((c) => c.distros.some((d) => d.mine && d.fix_version)).length;
  return { n: aff.length, high: aff.filter((c) => c.level >= 8).length, withFix, withoutFix: aff.length - withFix };
};

const browser = await chromium.launch({ executablePath: process.env.PW_CHROME, args: ["--no-sandbox"] });
try {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await ctx.newPage();
  await page.goto(`${base}/login`);
  await page.getByLabel("Benutzername").fill("admin");
  await page.getByLabel("Passwort").fill(pw);
  await page.getByRole("button", { name: "Anmelden" }).click();
  await page.waitForURL((u) => !u.pathname.startsWith("/login"));

  // A) Betrifft: Radiogruppe im Filterfenster, Zähler als reiner Text im Kopf.
  await page.goto(`${base}/cves`);
  const fbtn = page.getByRole("button", { name: /^Filter/ });
  await fbtn.waitFor();
  const text = page.getByTestId("affects-count");
  await text.getByText(/betreff/).waitFor();
  ok((await page.getByRole("button", { name: /^Meine Hosts/ }).count()) === 0, "keine Knöpfe „Meine Hosts / Alle“ auf der Seite (nur im Filterfenster)");
  ok((await text.locator("button, a").count()) === 0, "Zähler „N betreffen deine Hosts“ ist reiner Text");
  const n = Number((await text.innerText()).replace(/\./g, "").match(/\d+/)?.[0]);
  await fbtn.click();
  const grp = page.getByRole("dialog", { name: "Filter" }).getByRole("radiogroup", { name: "Betrifft" });
  ok((await grp.getByRole("radio", { name: "Meine Hosts" }).getAttribute("aria-checked")) === "true", "Standard „Meine Hosts“");
  await grp.getByRole("radio", { name: "Alle" }).click();
  await page.waitForURL(/affects=all/);
  ok((await grp.getByRole("radio", { name: "Alle" }).getAttribute("aria-checked")) === "true", "Auswahl „Alle“, URL enthält affects=all");
  await page.keyboard.press("Escape");
  await page.waitForFunction(() => document.querySelector('[data-testid="affects-count"]')?.textContent?.includes("betreff"));
  // Alte URL funktioniert weiter.
  await page.goto(`${base}/cves?affects=all`);
  await fbtn.waitFor();
  ok((await fbtn.innerText()).replace(/\s+/g, " ").trim() === "Filter 1", "alte URL ?affects=all: Filter zählt 1 Abweichung");
  await page.goto(`${base}/cves`);
  await fbtn.waitFor();
  // Satz stimmt mit der Trefferzahl überein: Zeilen der Liste (bis zum Limit) ≤ Zahl.
  const list = page.locator("table.tbl", { has: page.locator("caption", { hasText: "CVEs mit" }) });
  await list.locator("tbody tr").first().waitFor().catch(() => {});
  // Die Zeilen erscheinen in Schritten (30, dann der Rest): warten, bis die Anzahl steht.
  await page.waitForFunction(() => { const t = [...document.querySelectorAll("table.tbl")].find((x) => x.querySelector("caption")?.textContent?.startsWith("CVEs mit")); const n = t?.querySelectorAll("tbody tr").length ?? 0; const w = window; const prev = w.__n; w.__n = n; return n > 0 && prev === n; }, null, { polling: 400 });
  const listRows = await list.locator("tbody tr").count();
  ok(Number.isFinite(n) && (listRows === n || (listRows >= 100 && n >= listRows) || (listRows === 0 && n === 0)), `Satz (${n}) stimmt mit der Liste (${listRows}) überein`);

  // C) Mit erzeugten Zeilen: 5, 500, leer.
  let rows = gen(5);
  await page.route(/\/api\/v1\/cves\/scope-count/, (r) => r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ mine: rows.length, all: rows.length, affecting: expected(rows).n }) }));
  await page.route(/\/api\/v1\/cves\?/, (r) => r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(rows.slice(0, 100 * (new URL(r.request().url()).searchParams.get("limit") / 100 || 1))) }));
  const listTable = page.locator("table.tbl", { has: page.locator("caption", { hasText: "CVEs mit" }) });
  async function check(label) {
    await page.goto(`${base}/cves`);
    await page.getByTestId("cve-stats").waitFor();
    if (rows.length) await listTable.locator("tbody tr").first().waitFor();
    await sleep(300);
    const shown = rows.slice(0, 100);
    const e = expected(shown);
    const txt = (await page.getByTestId("cve-stats").innerText()).replace(/\./g, "");
    const cnt = (await page.getByTestId("affects-count").innerText()).replace(/\./g, "");
    if (rows.length) {
      ok(new RegExp(`^${e.n} betreff`).test(cnt) || new RegExp(`^1 betrifft`).test(cnt) && e.n === 1 || rows.length > 100, `${label}: Zähler zeigt ${e.n} („${cnt}“)`);
      ok(txt.includes(`hoch/kritisch ${e.high}`) && txt.includes(`${e.withFix} mit Fix im Archiv`) && txt.includes(`${e.withoutFix} ohne Fix`), `${label}: Kennzahlen stimmen mit der Liste überein (${e.high}/${e.withFix}/${e.withoutFix})`);
      ok((await page.getByTestId("cve-stats").locator("button, a").count()) === 0, `${label}: Kennzahlen sind nicht klickbar`);
    }
    const geo = await page.evaluate(() => {
      const t = document.querySelector("table.tbl:has(caption)")?.closest(".updatable");
      const tables = [...document.querySelectorAll("table.tbl")].find((x) => x.querySelector("caption")?.textContent?.startsWith("CVEs mit"));
      const r = tables?.getBoundingClientRect();
      return { docW: document.documentElement.scrollWidth - document.documentElement.clientWidth, h: r ? Math.round(r.height) : 0, rowsN: tables ? tables.querySelectorAll("tbody tr").length : 0 };
    });
    ok(geo.docW <= 0, `${label}: kein horizontaler Überlauf`);
    return geo;
  }
  let g = await check("5 Zeilen");
  ok(g.rowsN === 5, "5 Zeilen: Tabelle hat 5 Zeilen");
  const lastBottom = await page.evaluate(() => {
    const tb = [...document.querySelectorAll("table.tbl")].find((x) => x.querySelector("caption")?.textContent?.startsWith("CVEs mit"));
    const next = document.querySelector("p.mt-4");
    return Math.round(next.getBoundingClientRect().top - tb.getBoundingClientRect().bottom);
  });
  ok(lastBottom <= 24, `5 Zeilen: keine leere Fläche unter der Tabelle (${lastBottom}px bis zum Folgetext)`);
  // Filterzeile in einer Zeile (1440).
  const tops = await page.locator("#cve-filters > *").evaluateAll((els) => [...new Set(els.map((e) => Math.round(e.getBoundingClientRect().top / 8)))]);
  ok(tops.length === 1, `Filterzeile steht bei 1440 px in einer Zeile (${tops.length} Zeilen)`);
  if (shots) await page.screenshot({ path: `${shots}/cves-1440-5.png` });
  rows = gen(500);
  g = await check("500 Zeilen");
  ok(g.rowsN >= 30 && g.rowsN <= 100, `500 Zeilen: erste Seite (${g.rowsN} Zeilen) mit „Weitere laden“`);
  rows = [];
  await page.goto(`${base}/cves`);
  await page.getByText("Keine CVE betrifft deine Hosts").waitFor();
  const eh = await page.locator("div.border-y", { hasText: "Keine CVE betrifft deine Hosts" }).first().evaluate((e) => Math.round(e.getBoundingClientRect().height));
  ok(eh <= 140, `Leer-Zustand kompakt (${eh}px)`);
  await page.getByRole("button", { name: "Alle CVEs anzeigen" }).click();
  await page.waitForURL(/affects=all/);
  ok(true, "Leer-Zustand: „Alle CVEs anzeigen“ stellt Betrifft auf Alle");
  // Breiten, Zusatzspalten ab 1600, axe.
  rows = gen(5);
  for (const w of [390, 768, 1440, 1600, 1920]) {
    await page.setViewportSize({ width: w, height: 900 });
    await page.emulateMedia({ colorScheme: w % 2 ? "light" : "dark" });
    g = await check(`${w}px`);
    const hdrs = await listTable.locator("thead th").allInnerTexts();
    ok(!hdrs.some((x) => /Betroffene Hosts/.test(x)), `${w}px: keine eigene Spalte „Betroffene Hosts“ (in „Hosts“ zusammengelegt)`);
    const paketeVisible = await listTable.locator("thead th", { hasText: "Pakete" }).isVisible();
    if (w >= 1600) ok(paketeVisible, `${w}px: Zusatzspalte Pakete sichtbar`);
    else if (w >= 768) ok(!paketeVisible, `${w}px: ohne Zusatzspalte Pakete`);
    if (w === 1600) {
      const chips = await listTable.locator('ul[aria-label="Betroffene Hosts"]').first().innerText();
      ok(/host-/.test(chips), "1600px: Host-Namen als Chips");
      const mx = await listTable.locator('ul[aria-label="Betroffene Hosts"]').evaluateAll((els) => Math.max(...els.map((e) => e.querySelectorAll("li:not(:has(button))").length)));
      ok(mx <= 3, `1600px: höchstens 3 Namen je Zeile (${mx})`);
    }
    if (shots) await page.screenshot({ path: `${shots}/cves-${w}.png` });
    if (axeSrc && (w === 390 || w === 1920)) {
      await page.evaluate(axeSrc);
      const v = await page.evaluate(() => axe.run(document, { runOnly: ["wcag2a", "wcag2aa", "wcag21aa"] }).then((r) => r.violations.map((x) => `${x.id}: ${x.nodes.length}`)));
      ok(v.length === 0, `axe ${w}px: ${v.join(", ") || "keine Verstöße"}`);
    }
  }
  await ctx.close();
} finally {
  await browser.close();
}
