// E2E: Agents-Tabelle – Spaltenreihenfolge (ab 1024 px alle sieben Spalten, ohne Überlauf und Überlappung), Aktionen direkt nach „Zuletzt erreichbar“ (linksbündig, nicht am Rand), Agent-Version zuletzt,
// kein Überlauf, Tastaturbedienung des Menüs, unter 1024 px gestapelte Karten, axe. Nur lesend.
//   PW_MODULE=… PW_CHROME=… PW_PWFILE=<Datei mit Admin-Passwort> AXE_JS=… node scripts/e2e-agents-columns.mjs
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
const { chromium } = createRequire(import.meta.url)(process.env.PW_MODULE);
const pw = readFileSync(process.env.PW_PWFILE, "utf8").trim();
const axe = readFileSync(process.env.AXE_JS, "utf8");
const base = process.env.PW_BASE ?? "http://127.0.0.1:3100";
const ok = (c, m) => { console.log(c ? "OK  " : "FAIL", m); if (!c) process.exitCode = 1; };
const browser = await chromium.launch({ executablePath: process.env.PW_CHROME, args: ["--no-sandbox"] });
try {
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 }, reducedMotion: "reduce" });
  const page = await ctx.newPage();
  await page.goto(`${base}/login`);
  await page.getByLabel("Benutzername").fill("admin");
  await page.getByLabel("Passwort").fill(pw);
  await page.getByRole("button", { name: "Anmelden" }).click();
  await page.waitForURL((u) => !u.pathname.startsWith("/login"));
  for (const scheme of ["light", "dark"]) {
    await page.emulateMedia({ colorScheme: scheme, reducedMotion: "reduce" });
    for (const w of [390, 768, 1024, 1180, 1280, 1440, 1920, 2560]) {
      const tag = `${w}px ${scheme}`;
      await page.setViewportSize({ width: w, height: 900 });
      await page.goto(`${base}/agents`);
      await page.locator("table.tbl tbody tr").first().waitFor();
      await page.waitForTimeout(500);
      const m = await page.evaluate(() => {
        const t = document.querySelector("table.tbl");
        const r = (e) => e.getBoundingClientRect();
        const ths = [...t.querySelectorAll("thead th")].filter((h) => r(h).width > 0).map((h) => h.textContent.trim());
        const row = t.querySelector("tbody tr");
        const act = row.querySelector("td.cell-actions");
        const btn = act.querySelector("button");
        const menu = act.querySelectorAll("button")[1];
        const tr = r(t);
        // Waagerechter Überlauf der Tabelle in ihrem Rahmen und Überlappung/Abschneiden der Zellen.
        const wrap = t.parentElement;
        const rects = [...row.children].filter((c) => r(c).width > 0).map((c) => r(c));
        const overlap = rects.some((a, i) => i > 0 && a.left < rects[i - 1].right - 0.5);
        const clipped = [...t.querySelectorAll("th, td")].filter((c) => r(c).width > 0 && c.scrollWidth > c.clientWidth + 1).map((c) => c.textContent.trim().slice(0, 20));
        return { wrapOver: wrap.scrollWidth - wrap.clientWidth, overlap, clipped, ths, stacked: getComputedStyle(t.querySelector("tbody")).display === "block", over: document.documentElement.scrollWidth - innerWidth,
          btnLeft: r(btn).left, actLeft: r(act).left, padL: parseFloat(getComputedStyle(act).paddingLeft), btnW: r(btn).width, btnH: r(btn).height, menuW: r(menu).width, menuH: r(menu).height,
          menuRight: r(menu).right, tblRight: tr.right, tblLeft: tr.left,
          cells: [...row.children].filter((c) => r(c).width > 0).map((c) => c.getAttribute("data-label") ?? (c.classList.contains("cell-actions") ? "Aktionen" : "Name")) };
      });
      if (w >= 1024) {
        const all7 = ["Name", "Hostname laut Agent", "Distribution", "Zuletzt gemeldet", "Zuletzt erreichbar", "Aktionen", "Agent-Version"];
        ok(m.ths.length === 7 && all7.every((x, i) => m.ths[i]?.startsWith(x)), `${tag}: alle sieben Spalten in der Vorgabe-Reihenfolge (${m.ths.join(" | ")})`);
        ok(m.wrapOver <= 0, `${tag}: Tabelle ohne waagerechten Überlauf im Rahmen (${m.wrapOver})`);
        ok(!m.overlap && m.clipped.length === 0, `${tag}: keine Überlappung, nichts abgeschnitten (${m.clipped.join(", ")})`);
        const want = ["Name", "Hostname laut Agent", "Distribution", "Zuletzt gemeldet"];
        ok(want.every((x, i) => m.ths[i]?.startsWith(x)), `${tag}: Spaltenfolge beginnt mit ${want.join(", ")} (${m.ths.join(" | ")})`);
        const iA = m.ths.indexOf("Aktionen");
        ok(m.ths[m.ths.length - 1] === "Agent-Version", `${tag}: Agent-Version zuletzt`);
        ok(m.ths[iA - 1].startsWith("Zuletzt erreichbar") && iA === m.ths.length - 2, `${tag}: Aktionen direkt nach „Zuletzt erreichbar“`);
        ok(Math.abs(m.btnLeft - m.actLeft - m.padL) <= 8, `${tag}: Knopf linksbündig in der Zelle (${(m.btnLeft - m.actLeft).toFixed(1)} / ${m.padL})`);
        ok(m.tblRight - m.menuRight > 16, `${tag}: Knopfreihe nicht am rechten Rand (${(m.tblRight - m.menuRight).toFixed(1)} px Abstand)`);
        ok(Math.abs(m.btnH - 32) <= 0.5 && Math.abs(m.menuH - 32) <= 0.5 && Math.abs(m.menuW - 32) <= 0.5, `${tag}: Knöpfe 32 px (${m.btnH}, Menü ${m.menuW}×${m.menuH})`);
        ok(!m.stacked, `${tag}: Tabelle (keine Karten)`);
      } else {
        ok(m.stacked, `${tag}: gestapelte Karten`);
        ok(Math.abs(m.btnH - (w < 768 ? 44 : 32)) <= 0.5, `${tag}: Knopfhöhe (${m.btnH})`);
      }
      ok(m.over <= 0, `${tag}: kein Seitenüberlauf (${m.over})`);
      if (w === 1280 || w === 390) {
        // Tastatur: Menü per Enter öffnen, Escape schließt und gibt den Fokus zurück.
        const menuBtn = page.getByRole("button", { name: /Weitere Aktionen für/ }).first();
        await menuBtn.focus();
        await page.keyboard.press("Enter");
        const item = page.getByRole("button", { name: /Token erneuern für/ }).first();
        ok(await item.isVisible().catch(() => false) || (await page.getByText("Token erneuern").first().isVisible().catch(() => false)), `${tag}: Menü per Tastatur geöffnet`);
        await page.keyboard.press("Escape");
        ok(await menuBtn.evaluate((e) => document.activeElement === e), `${tag}: Fokus zurück am Menüknopf`);
        await page.evaluate(axe);
        const v = await page.evaluate(() => globalThis.axe.run(document, { runOnly: ["wcag2a", "wcag2aa", "wcag22aa", "best-practice"] }).then((r) => r.violations.filter((x) => !["region", "landmark-one-main", "page-has-heading-one"].includes(x.id)).map((x) => `${x.id}:${x.nodes[0]?.target}`)));
        ok(v.length === 0, `${tag}: axe ${v.join(", ")}`);
      }
    }
  }
} finally {
  await browser.close();
}
