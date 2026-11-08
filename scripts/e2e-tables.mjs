// E2E: Tabellen Hosts, CVEs, Agents (und CVE-Quellen): gleiche Spaltenabstände, Überschriften unverkürzt, kein Überlauf,
// Zellen vertikal mittig, Hostnamen in der CVE-Tabelle als Links (Maus, Strg, Tastatur, "+N"), Sortierung nach Hosts, axe.
// Die CVE-Liste und die Hostnamen→Adresse kommen aus Mocks; nur Lesezugriffe gegen den Server.
//   PW_MODULE=… PW_CHROME=… PW_PWFILE=<Datei> AXE_JS=… [PW_SHOTS=<Ordner>] node scripts/e2e-tables.mjs
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { measure } from "./lib/gaps.mjs";
const { chromium } = createRequire(import.meta.url)(process.env.PW_MODULE);
const pw = readFileSync(process.env.PW_PWFILE, "utf8").trim();
const axeSrc = readFileSync(process.env.AXE_JS, "utf8");
const base = process.env.PW_BASE ?? "http://127.0.0.1:3100";
const shots = process.env.PW_SHOTS;
const ok = (c, m) => { console.log(c ? "OK  " : "FAIL", m); if (!c) process.exitCode = 1; };
const MAXDEV = 8; // erlaubte Abweichung der Abstände in px

const cve = (i, hosts) => ({
  id: `CVE-2026-${30000 + i}`, description: `Beispiel ${i}: ${"ein längerer Beschreibungstext über mehrere Zeilen ".repeat(4)}`, priority: "high", level: 5, published_at: "2026-10-01T00:00:00Z",
  updated_at: null, last_synced_at: "2026-11-01T00:00:00Z", watched: false, note: null, exploited: false,
  hosts_vulnerable: hosts.length, hosts_fix_pending: 0, hosts_reboot: 0, hosts_unknown: 0, affected_hosts: hosts,
  distros: [{ source: "ubuntu", release: "resolute", status: "open", package: "linux", fix_version: null, updated_at: "2026-11-01T00:00:00Z", mine: true }],
  hidden_releases: 0,
});

const browser = await chromium.launch({ executablePath: process.env.PW_CHROME, args: ["--no-sandbox"] });
try {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await ctx.newPage();
  await page.goto(`${base}/login`);
  await page.getByLabel("Benutzername").fill("admin");
  await page.getByLabel("Passwort").fill(pw);
  await page.getByRole("button", { name: "Anmelden" }).click();
  await page.waitForURL((u) => !u.pathname.startsWith("/login"));
  const realHosts = await page.evaluate(() => fetch("/api/v1/hosts").then((r) => r.json()));
  const real = realHosts[0];

  /** Alle Paare benachbarter Spalten haben (fast) denselben Abstand; Köpfe überlappen nie. */
  const gaps = async (label, sel, { skip = [], assertGaps = true } = {}) => {
    for (const w of [1440, 1920]) for (const scheme of ["light", "dark"]) {
      await page.emulateMedia({ colorScheme: scheme });
      await page.setViewportSize({ width: w, height: 900 });
      await page.waitForTimeout(250);
      const r = await page.evaluate(measure, sel);
      const L = `${label} ${w}/${scheme}`;
      const want = w >= 1600 ? 32 : 24;
      const used = r.pairs.filter((p) => !skip.some((s) => p.pair.includes(s)));
      const dev = Math.max(...used.map((p) => Math.abs(p.gap - used[0].gap)));
      if (!assertGaps) console.log(`INFO ${L}: Abstände ${r.pairs.map((p) => `${p.pair.replace(/ → /, ">")}=${p.gap}`).join(" ")}`);
      else ok(dev <= MAXDEV, `${L}: Abstand benachbarter Spalten gleich (Abweichung ${dev}px; ${used.map((p) => `${p.pair.replace(/ → /, ">")}=${p.gap}`).join(" ")})`);
      if (assertGaps) ok(used.every((p) => Math.abs(p.gap - want) <= MAXDEV), `${L}: Abstand ≈ ${want}px (${used.map((p) => `${p.pair.replace(/ → /, ">")}=${p.gap}`).join(" ")})`);
      ok(r.pairs.every((p) => !(p.headGap < 0)), `${L}: Überschriften überlappen keinen Nachbarn (${r.pairs.filter((p) => p.headGap < 0).map((p) => p.pair + "=" + p.headGap).join(", ") || "ok"})`);
      ok(r.overflow <= 0, `${L}: kein horizontaler Überlauf`);
      const cut = await page.evaluate((s) => [...document.querySelectorAll(`${s} thead th`)].filter((th) => th.offsetParent && !th.classList.contains("fill")).filter((th) => { const el = th.querySelector("button, .th-pad") ?? th; const b = el.getBoundingClientRect(), t = th.getBoundingClientRect(); return el.scrollWidth > el.clientWidth + 1 || b.right > t.right + 1 || b.left < t.left - 1; }).map((th) => th.innerText.trim()), sel);
      ok(cut.length === 0, `${L}: Überschriften nicht abgeschnitten (${cut.join(", ") || "alle vollständig"})`);
    }
  };

  // Hostliste (echte Daten, eine Zeile).
  await page.goto(`${base}/`);
  await page.locator("table.tbl tbody tr").first().waitFor();
  await gaps("Hosts", "table.tbl");
  const mid = async (sel) => page.evaluate((s) => {
    const row = document.querySelector(`${s} tbody tr`);
    const centers = [...row.children].filter((c) => c.offsetParent && !c.classList.contains("fill") && !c.classList.contains("cell-star") && c.innerText.trim()).map((c) => {
      const w = document.createTreeWalker(c, NodeFilter.SHOW_TEXT); let top = Infinity, bot = -Infinity;
      for (let n = w.nextNode(); n; n = w.nextNode()) { if (!n.textContent.trim() || n.parentElement.closest(".sr-only")) continue; const r = document.createRange(); r.selectNodeContents(n); for (const b of r.getClientRects()) { top = Math.min(top, b.top); bot = Math.max(bot, b.bottom); } }
      return (top + bot) / 2;
    });
    return { spread: Math.max(...centers) - Math.min(...centers), n: centers.length };
  }, sel);
  await page.setViewportSize({ width: 1440, height: 900 });
  const mh = await mid("table.tbl");
  ok(mh.spread <= 12, `Hosts: Zellen einer Zeile stehen mittig (Streuung der Mitten ${mh.spread.toFixed(1)}px, ${mh.n} Zellen; Zweizeiler dürfen um eine halbe Zeile abweichen)`);
  const va = await page.evaluate(() => [...new Set([...document.querySelectorAll("table.tbl tbody td")].map((td) => getComputedStyle(td).verticalAlign))]);
  ok(va.length === 1 && va[0] === "middle", `Hosts: vertical-align middle (${va})`);
  await page.evaluate(axeSrc);
  let v = await page.evaluate(() => axe.run(document, { runOnly: ["wcag2a", "wcag2aa", "wcag21aa", "best-practice"] }).then((r) => r.violations.map((x) => `${x.id}: ${x.nodes.length}`)));
  ok(v.length === 0, `Hosts: axe ${v.join(", ") || "keine Verstöße"}`);
  if (shots) await page.screenshot({ path: `${shots}/tables-hosts-1440.png` });

  // Agents.
  await page.goto(`${base}/agents`);
  await page.locator("table.tbl tbody tr").first().waitFor();
  await gaps("Agents", "table.tbl");

  // CVE-Seite mit Mock: Hostnamen als Links.
  const hostsMock = [...realHosts, ...["web-02", "db-01", "db-02", "app-01"].map((name, i) => ({ ...real, id: 9001 + i, name }))];
  const rows = [cve(1, [real.name]), cve(2, [real.name, "web-02", "db-01", "db-02", "app-01"]), cve(3, ["db-01", "web-02"])];
  const reqs = [];
  await page.route(/\/api\/v1\/hosts$/, (r) => r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(hostsMock) }));
  await page.route(/\/api\/v1\/cves\/scope-count/, (r) => r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify({ mine: 3, all: 3, affecting: 3 }) }));
  await page.route(/\/api\/v1\/cves\?/, (r) => { reqs.push(r.request().url()); r.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(rows) }); });
  const list = page.locator("table.tbl", { has: page.locator("caption", { hasText: "CVEs mit" }) });
  // querySelector kennt kein :text-matches: Tabellen anhand ihrer Überschrift markieren.
  const tag = (cap, name) => page.evaluate(([c, n]) => { for (const t of document.querySelectorAll("table.tbl")) if (t.querySelector("caption")?.textContent?.startsWith(c)) t.setAttribute("data-t", n); }, [cap, name]);
  const listSel = 'table[data-t="cves"]';
  await page.goto(`${base}/cves`);
  await list.locator("tbody tr").nth(2).waitFor();
  await page.waitForTimeout(500);
  await tag("CVEs mit", "cves");

  const hdr = (await list.locator("thead th").allInnerTexts()).map((t) => t.replace(/\s+/g, " ").trim());
  ok(!hdr.some((t) => /Betroffene Hosts/.test(t)) && hdr.some((t) => /^Hosts/.test(t)), `CVE-Tabelle: Spalten „Hosts“ und „Betroffene Hosts“ zusammengelegt (${hdr.join(" | ")})`);
  const firstRow = list.locator("tbody tr").nth(0);
  const chip = firstRow.locator('ul[aria-label="Betroffene Hosts"] a').first();
  ok((await chip.count()) === 1 && (await chip.getAttribute("href")) === `/hosts/${real.id}`, "Chip ist ein Link zur Host-Seite");
  ok((await chip.getAttribute("title")) === `Zu ${real.name} wechseln`, "Tooltip „Zu … wechseln“");
  ok((await chip.evaluate((e) => getComputedStyle(e).cursor)) === "pointer", "Chip: Zeiger");
  // vertikal mittig
  const mm = await mid(listSel);
  ok(mm.spread <= 14, `CVE-Tabelle: Zellen einer Zeile mittig (Streuung ${mm.spread.toFixed(1)}px, ${mm.n} Zellen)`);
  const lineY = await firstRow.evaluate((tr) => {
    const chipEl = tr.querySelector('ul[aria-label="Betroffene Hosts"] a'); const cell = chipEl.closest("td"); const cr = cell.getBoundingClientRect();
    const items = [...cell.children].map((c) => c.getBoundingClientRect()); const top = Math.min(...items.map((b) => b.top)), bot = Math.max(...items.map((b) => b.bottom));
    return { cellMid: (cr.top + cr.bottom) / 2, contentMid: (top + bot) / 2 };
  });
  ok(Math.abs(lineY.cellMid - lineY.contentMid) <= 2, `Hosts-Zelle: Inhalt mittig zur Zeile (Abweichung ${Math.abs(lineY.cellMid - lineY.contentMid).toFixed(1)}px)`);
  const vaC = await list.evaluate((t) => [...new Set([...t.querySelectorAll("tbody td")].map((td) => getComputedStyle(td).verticalAlign))]);
  ok(vaC.length === 1 && vaC[0] === "middle", `CVE-Tabelle: vertical-align middle (${vaC})`);

  // Maus, Strg-Klick, Tastatur
  const rowChipsMax = await list.locator("tbody tr").nth(1).locator('ul[aria-label="Betroffene Hosts"] > li').evaluateAll((els) => els.filter((e) => !e.querySelector("button")).length);
  ok(rowChipsMax === 3, `höchstens 3 Chips sichtbar (${rowChipsMax})`);
  let [tab] = await Promise.all([ctx.waitForEvent("page"), chip.click({ modifiers: ["Control"] })]);
  await tab.waitForURL(`**/hosts/${real.id}`);
  ok(true, "Strg-Klick auf den Chip öffnet einen neuen Tab");
  await tab.close();
  [tab] = await Promise.all([ctx.waitForEvent("page"), chip.click({ button: "middle" })]);
  await tab.waitForURL(`**/hosts/${real.id}`);
  ok(true, "Mittelklick auf den Chip öffnet einen neuen Tab");
  await tab.close();
  await chip.focus();
  await page.keyboard.press("Tab");
  await page.keyboard.press("Shift+Tab");
  const ring = await chip.evaluate((e) => { const s = getComputedStyle(e); return `${s.outlineStyle} ${s.outlineWidth}`; });
  ok(ring === "solid 2px", `Chip: Fokusring sichtbar (${ring})`);
  await page.keyboard.press("Enter");
  await page.waitForURL(`**/hosts/${real.id}`);
  ok(true, "Tastatur: Enter auf dem Chip öffnet die Host-Seite");
  await page.goto(`${base}/cves`);
  await list.locator("tbody tr").nth(2).waitFor();

  // "+N"
  const r2 = list.locator("tbody tr").nth(1);
  const more = r2.getByRole("button", { name: /weitere Hosts/ });
  ok((await more.count()) === 1 && /\+2/.test(await more.innerText()), "„+2“-Schaltfläche an der Zeile mit 5 Hosts");
  ok((await more.getAttribute("aria-expanded")) === "false", "„+N“ zunächst zu");
  await more.focus();
  await page.keyboard.press("Enter");
  const all = r2.locator('ul[aria-label^="Alle betroffenen Hosts"] a');
  ok((await more.getAttribute("aria-expanded")) === "true" && (await all.count()) === 5, "„+N“ listet alle 5 Hosts als Links");
  ok((await all.evaluateAll((els) => els.map((e) => e.getAttribute("href")))).every((h) => /^\/hosts\/\d+$/.test(h)), "alle Einträge der Liste verweisen auf Host-Seiten");

  // Sortierung nach Hosts
  // Standard ist „nach Hosts absteigend“; ein Klick auf die Überschrift kehrt die Richtung um (und zurück).
  const hostsTh = list.locator("thead th", { hasText: /^Hosts/ });
  const sortBtn = hostsTh.getByRole("button");
  await hostsTh.waitFor();
  const s0 = await hostsTh.getAttribute("aria-sort");
  await sortBtn.click();
  // Richtung steht in der URL (Standard descending lässt den Parameter weg).
  await page.waitForURL(/dir=asc/, { timeout: 10000 }).catch(() => {});
  await page.waitForTimeout(500);
  const s1 = await list.locator("thead th", { hasText: /^Hosts/ }).getAttribute("aria-sort");
  ok(s0 !== s1 && s1 !== "none" && s1 !== null, `Sortierung nach Hosts über die Überschrift (aria-sort ${s0} → ${s1}, URL ${new URL(page.url()).search || "-"})`);
  await list.locator("thead th", { hasText: /^Hosts/ }).getByRole("button").click();
  await page.waitForTimeout(700);
  ok((await list.locator("thead th", { hasText: /^Hosts/ }).getAttribute("aria-sort")) === s0, "zweiter Klick kehrt zurück");

  // Abstände und Überschriften der CVE-Liste (Beschreibung ist Fließtext: Paare mit ihr zählen nicht).
  await tag("CVEs mit", "cves");
  await gaps("CVEs", listSel, { skip: ["Beschreibung", "Beobachten"] });
  // Chips mobil: Trefferfläche
  await page.setViewportSize({ width: 390, height: 844 });
  await page.waitForTimeout(300);
  const small = await list.locator('ul[aria-label="Betroffene Hosts"] a').evaluateAll((els) => els.filter((e) => e.offsetParent).map((e) => e.getBoundingClientRect().height).filter((h) => h < 44).length);
  ok(small === 0, `mobil: Chips mindestens 44px hoch (${small} zu klein)`);
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.evaluate(axeSrc);
  v = await page.evaluate(() => axe.run(document, { runOnly: ["wcag2a", "wcag2aa", "wcag21aa", "best-practice"] }).then((r) => r.violations.map((x) => `${x.id}: ${x.nodes.length}`)));
  ok(v.length === 0, `CVEs: axe ${v.join(", ") || "keine Verstöße"}`);
  if (shots) await page.screenshot({ path: `${shots}/tables-cves-1440.png`, fullPage: true });

  // CVE-Quellen (Tabelle oben auf der CVE-Seite): Überschriften, Überlauf; Abstände nur grob (feste Spaltenbreiten gegen Wackeln).
  await tag("Zustand der CVE-Quellen", "feeds");
  await gaps("Quellen", 'table[data-t="feeds"]', { assertGaps: false }).catch((e) => ok(false, `Quellen: ${e.message.split("\n")[0]}`));
} finally {
  await browser.close();
}
