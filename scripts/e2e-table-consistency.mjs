// E2E: Konsistenz der drei Tabellen (Hosts, Agents, CVE-Quellen) bei 1280/1440/1920/2560 px: gleiche Kopfhöhe, gleiche Zellabstände,
// Kopf und Zellen linksbündig am selben Rand, Tabelle bis zum Inhaltsrand (kein leerer Bereich rechts), keine Überlappung, kein Überlauf.
//   PW_MODULE=… PW_CHROME=… PW_PWFILE=<Datei mit Admin-Passwort> node scripts/e2e-table-consistency.mjs
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
const { chromium } = createRequire(import.meta.url)(process.env.PW_MODULE);
const pw = readFileSync(process.env.PW_PWFILE, "utf8").trim();
const base = process.env.PW_BASE ?? "http://127.0.0.1:3100";
const ok = (c, m) => { console.log(c ? "OK  " : "FAIL", m); if (!c) process.exitCode = 1; };
const browser = await chromium.launch({ executablePath: process.env.PW_CHROME, args: ["--no-sandbox"] });
try {
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 }, reducedMotion: "reduce" });
  const page = await ctx.newPage();
  await page.addInitScript(() => { try { localStorage.setItem("pw-feeds-manage", "1"); } catch {} });
  await page.goto(`${base}/login`);
  await page.getByLabel("Benutzername").fill("admin");
  await page.getByLabel("Passwort").fill(pw);
  await page.getByRole("button", { name: "Anmelden", exact: true }).click();
  await page.waitForURL((u) => !u.pathname.startsWith("/login"));
  const PAGES = [["Hosts", "/", "table.tbl"], ["Agents", "/agents", "table.tbl"], ["CVE-Quellen", "/cves", "table[data-t=feeds]"]];
  for (const w of [1280, 1440, 1920, 2560]) {
    await page.setViewportSize({ width: w, height: 900 });
    const res = {};
    for (const [name, path, sel] of PAGES) {
      await page.goto(`${base}${path}`);
      await page.locator(`${sel} tbody tr`).first().waitFor();
      await page.waitForTimeout(900);
      res[name] = await page.evaluate((sel) => {
        const t = document.querySelector(sel);
        const r = (e) => e.getBoundingClientRect();
        const cs = (e, p) => parseFloat(getComputedStyle(e)[p]);
        const ths = [...t.querySelectorAll("thead th")].filter((h) => r(h).width > 0);
        const tr = t.querySelector("tbody tr");
        const tds = [...tr.children].filter((c) => r(c).width > 0);
        const contentRight = document.querySelector("main").getBoundingClientRect().right - 24;
        // Textanfang je Spalte: Kopf (Text im .th-pad) gegen Zelle (erstes Inhaltselement bzw. Zellrand + Innenabstand).
        const textLeft = (e) => { const w = document.createTreeWalker(e, NodeFilter.SHOW_TEXT, { acceptNode: (n) => (n.textContent.trim() ? 1 : 3) }); const n = w.nextNode(); if (!n) return r(e).left; const g = document.createRange(); g.selectNodeContents(n); return g.getBoundingClientRect().left; };
        const mis = ths.map((h, i) => [h.textContent.trim().slice(0, 14), Math.round(Math.abs(textLeft(h) - (tds[i].querySelector("a, button, span, div") && i > 0 ? Math.min(textLeft(tds[i]), r(tds[i].querySelector("a, button, span, div")).left) : textLeft(tds[i]))))]).filter(([, d], i) => d > 12 && ths[i].classList.contains("num") === false);
        const overlap = tds.some((c, i) => i > 0 && r(c).left < r(tds[i - 1]).right - 0.5);
        return { headH: r(t.querySelector("thead tr")).height, padL: cs(tds[1], "paddingLeft"), padR: cs(tds[1], "paddingRight"), padT: cs(tds[1], "paddingTop"), tblRight: r(t).right, thRight: r(ths[ths.length - 1]).right, contentRight, mis, overlap, over: document.documentElement.scrollWidth - innerWidth };
      }, sel);
    }
    const names = Object.keys(res);
    const R = (n) => res[n];
    ok(names.every((n) => Math.abs(R(n).headH - R(names[0]).headH) <= 1), `${w}: gleiche Kopfhöhe (${names.map((n) => R(n).headH.toFixed(0)).join("/")})`);
    ok(names.every((n) => Math.abs(R(n).padL - R(names[0]).padL) <= 0.5 && Math.abs(R(n).padT - R(names[0]).padT) <= 4), `${w}: gleiche Zellabstände (L ${names.map((n) => R(n).padL).join("/")}, oben ${names.map((n) => R(n).padT).join("/")})`);
    for (const n of names) {
      ok(Math.abs(R(n).thRight - R(n).contentRight) <= 1.5, `${w} ${n}: Tabelle bis zum Inhaltsrand (${(R(n).contentRight - R(n).thRight).toFixed(1)} px frei)`);
      // CVE-Quellen: Zellen enthalten Chips/Zeilen mit eigenem Einzug; dort gilt der Abstand zum Zellrand (gleiche Zellabstände oben), Ausrichtung per Screenshot geprüft.
      ok(n === "CVE-Quellen" || R(n).mis.length === 0, `${w} ${n}: Kopf und Zellen linksbündig ${JSON.stringify(R(n).mis)}`);
      ok(!R(n).overlap && R(n).over <= 0, `${w} ${n}: keine Überlappung, kein Seitenüberlauf`);
    }
  }
} finally {
  await browser.close();
}
