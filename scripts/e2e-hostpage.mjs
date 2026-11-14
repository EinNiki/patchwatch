// E2E: Host-Seite (Liste passt sich dem Inhalt an, Host-Details rechts ab 1280 px, kein Überlauf, kein Layoutsprung, axe).
// Die CVE-Liste wird per page.route mit 5 bzw. 3.000 erzeugten Zeilen nachgestellt; der Server bekommt keine Schreibzugriffe.
//   PW_MODULE=… PW_CHROME=… PW_PWFILE=<Datei mit Admin-Passwort> AXE_JS=<axe.min.js> [PW_SHOTS=<Ordner>] node scripts/e2e-hostpage.mjs
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
const { chromium } = createRequire(import.meta.url)(process.env.PW_MODULE);
const pw = readFileSync(process.env.PW_PWFILE, "utf8").trim();
const axeSrc = process.env.AXE_JS ? readFileSync(process.env.AXE_JS, "utf8") : null;
const base = process.env.PW_BASE ?? "http://127.0.0.1:3100";
const shots = process.env.PW_SHOTS;
const ok = (c, m) => { console.log(c ? "OK  " : "FAIL", m); if (!c) process.exitCode = 1; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const gen = (n) => Array.from({ length: n }, (_, i) => ({
  cve_id: `CVE-2026-${String(10000 + i)}`, status: "vulnerable", reason: "Fix im Archiv", computed_at: "2026-11-01T10:00:00Z",
  sources: [{ source: "debian", release: "trixie", package: "linux", status: "resolved", fix_version: "6.12.5-1" }],
  description: `Beispiel ${i}: ein längerer Beschreibungstext, der in der Zeile abgeschnitten werden darf, damit das Raster stabil bleibt.`, priority: "medium", watched: false,
  reviewed_at: null, reviewed_by: null, level: 5 + (i % 5), fix_version: "6.12.5-1", source: "debian", published_at: "2026-10-01T00:00:00Z",
}));

const browser = await chromium.launch({ executablePath: process.env.PW_CHROME, args: ["--no-sandbox"] });
try {
  let page;
  async function open(w, h = 900, scheme = "dark") {
    // Eine Sitzung für den ganzen Lauf (der Login ist ratenbegrenzt); Breite und Farbschema werden umgestellt.
    if (page) {
      await page.unrouteAll({ behavior: "ignoreErrors" });
      await page.setViewportSize({ width: w, height: h });
      await page.emulateMedia({ colorScheme: scheme });
      return page;
    }
    const ctx = await browser.newContext({ viewport: { width: w, height: h }, colorScheme: scheme });
    page = await ctx.newPage();
    await page.goto(`${base}/login`);
    await page.getByLabel("Benutzername").fill("admin");
    await page.getByLabel("Passwort").fill(pw);
    await page.getByRole("button", { name: "Anmelden", exact: true }).click();
    await page.waitForURL((u) => !u.pathname.startsWith("/login"));
    return page;
  }
  await open(1440);
  const hosts = await page.evaluate(() => fetch("/api/v1/hosts").then((r) => r.json()));
  const host = hosts[0];
  ok(!!host, `Host gefunden (${host?.name})`);
  let rows = 5;
  async function mock() {
    await page.route(new RegExp(`/api/v1/hosts/${host.id}/cves\\?(?!limit=1$)`), async (r) => {
      const url = new URL(r.request().url());
      if (url.pathname.endsWith("/groups")) return r.fallback();
      const real = await (await r.fetch()).json();
      const items = gen(rows).slice(0, Number(url.searchParams.get("limit") ?? 200));
      return r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ ...real, items, total: rows }) });
    });
  }
  async function metrics() {
    return page.evaluate(() => {
      const reg = document.querySelector('[role="region"][aria-label$=", Liste"]');
      if (!reg) return null;
      const r = reg.getBoundingClientRect();
      return { top: Math.round(r.top + scrollY), h: Math.round(r.height), sh: reg.scrollHeight, ch: reg.clientHeight, rows: reg.querySelectorAll("li").length, docW: document.documentElement.scrollWidth - document.documentElement.clientWidth, docH: document.documentElement.scrollHeight, vh: innerHeight };
    });
  }
  async function axe(label) {
    if (!axeSrc) return;
    await page.evaluate(axeSrc);
    const v = await page.evaluate(() => axe.run(document, { runOnly: ["wcag2a", "wcag2aa", "wcag21aa"] }).then((r) => r.violations.map((x) => `${x.id}: ${x.nodes.length}`)));
    ok(v.length === 0, `axe ${label}: ${v.join(", ") || "keine Verstöße"}`);
  }

  // 1) Fünf Zeilen: Liste so hoch wie der Inhalt, keine leere Fläche.
  await mock();
  await page.goto(`${base}/hosts/${host.id}`);
  await page.waitForSelector('[role="region"][aria-label$=", Liste"]');
  await page.waitForFunction(() => document.querySelectorAll('[role="region"][aria-label$=", Liste"] li').length === 5);
  let m = await metrics();
  ok(m.h <= 5 * 32 + 2 + 2 && m.sh - m.ch <= 1, `5 Zeilen: Liste ${m.h}px hoch = Inhalt (${5 * 32 + 2}px), kein Innen-Scroll`);
  // Layoutsprung: Position und Höhe bleiben nach dem Nachladen gleich.
  await sleep(1800);
  const m2 = await metrics();
  ok(Math.abs(m2.top - m.top) <= 1 && Math.abs(m2.h - m.h) <= 1, `kein Layoutsprung beim Nachladen (top ${m.top}→${m2.top}, Höhe ${m.h}→${m2.h})`);
  const gap = await page.evaluate(() => {
    const reg = document.querySelector('[role="region"][aria-label$=", Liste"]').getBoundingClientRect();
    const next = document.querySelector("#updates, #hist")?.getBoundingClientRect();
    return next ? Math.round(next.top - reg.bottom) : 0;
  });
  ok(gap <= 120, `Abstand unter der Liste zum nächsten Abschnitt ${gap}px (nur Abschnittsabstand)`);
  if (shots) await page.screenshot({ path: `${shots}/host-1440-5.png` });
  await axe("1440 / 5 Zeilen");
  ok((await page.locator("aside[aria-labelledby=facts]").isVisible()) && m.docW <= 0, "1440: Host-Details rechts sichtbar, kein horizontaler Überlauf");

  // 2) 3.000 Zeilen: nur die Liste scrollt innen.
  rows = 3000;
  await page.reload();
  await page.waitForFunction(() => document.querySelectorAll('[role="region"][aria-label$=", Liste"] li').length > 20);
  m = await metrics();
  ok(m.sh > m.ch && m.h <= m.vh, `3.000 Zeilen: Liste scrollt innen (${m.ch}px sichtbar, ${m.sh}px Inhalt)`);
  ok(m.docH < m.vh * 3, `Seite wächst nicht mit den Zeilen (Seitenhöhe ${m.docH}px)`);
  ok(m.rows < 200, `virtualisiert (${m.rows} Zeilen im DOM)`);

  // 3) Breiten: Spalte rechts ab 1280, Aufklappabschnitt darunter, Überlauf, Zusatzspalten ab 1600.
  rows = 5;
  for (const w of [390, 768, 1024, 1279, 1280, 1440, 1600, 1920]) {
    await open(w, 900, w % 2 ? "light" : "dark");
    await mock();
    await page.goto(`${base}/hosts/${host.id}`);
    await page.waitForFunction(() => document.querySelectorAll('[role="region"][aria-label$=", Liste"] li').length === 5);
    m = await metrics();
    const side = await page.locator("aside[aria-labelledby=facts]").isVisible();
    const det = await page.locator("details", { hasText: "Host-Details" }).first().isVisible();
    ok(side === (w >= 1280) && det === (w < 1280), `${w}px: ${w >= 1280 ? "Spalte rechts" : "aufklappbarer Abschnitt"} (aside ${side}, details ${det})`);
    ok(m.docW <= 0, `${w}px: kein horizontaler Überlauf (${m.docW})`);
    const cols = await page.locator('[role="region"][aria-label$=", Liste"] li').first().evaluate((li) => getComputedStyle(li).gridTemplateColumns.split(" ").length);
    if (w >= 1600) ok(cols >= 8, `${w}px: Zusatzspalten Paket, Fix-Version, Quelle (${cols} Spalten)`);
    if (w >= 768 && w < 1600) ok(cols <= 6, `${w}px: ohne Zusatzspalten (${cols} Spalten)`);
    if (shots) await page.screenshot({ path: `${shots}/host-${w}.png` });
    if (w === 390 || w === 1920) await axe(`${w}`);
  }
  // Sticky: die rechte Spalte läuft mit.
  await open(1440, 600);
  rows = 3000;
  await mock();
  await page.goto(`${base}/hosts/${host.id}`);
  await page.waitForSelector("aside[aria-labelledby=facts]");
  const before = await page.locator("aside[aria-labelledby=facts]").evaluate((a) => Math.round(a.getBoundingClientRect().top));
  await page.evaluate(() => scrollTo(0, 400));
  await sleep(200);
  const after = await page.locator("aside[aria-labelledby=facts]").evaluate((a) => Math.round(a.getBoundingClientRect().top));
  ok(after >= 0 && after <= 20, `Host-Details bleibt beim Scrollen sichtbar (oben ${before} → ${after})`);
} finally {
  await browser.close();
}
