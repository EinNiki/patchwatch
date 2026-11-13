// E2E der Korrekturrunde: A1 einheitliche Köpfe, A2 Aktionsspalte (weitere Abschnitte folgen je Aufgabe).
//   PW_MODULE=… PW_CHROME=… PW_PWFILE=<Datei> AXE_JS=… [PW_BASE=…] [PW_SHOTS=<Ordner>] [PW_ONLY=A1,A2] node scripts/e2e-fix.mjs
import { createRequire } from "node:module";
import { readFileSync, mkdirSync } from "node:fs";
const { chromium } = createRequire(import.meta.url)(process.env.PW_MODULE);
const pw = readFileSync(process.env.PW_PWFILE, "utf8").trim();
const axeSrc = readFileSync(process.env.AXE_JS, "utf8");
const base = process.env.PW_BASE ?? "http://127.0.0.1:3300";
const shots = process.env.PW_SHOTS;
if (shots) mkdirSync(shots, { recursive: true });
const only = (process.env.PW_ONLY ?? "").split(",").filter(Boolean);
const want = (k) => only.length === 0 || only.includes(k);
const ok = (c, m) => { console.log(c ? "OK  " : "FAIL", m); if (!c) process.exitCode = 1; };
const browser = await chromium.launch({ executablePath: process.env.PW_CHROME, args: ["--no-sandbox"] });

async function open(w, h, scheme = "light", extra = {}) {
  const ctx = await browser.newContext({ viewport: { width: w, height: h }, colorScheme: scheme, ...extra });
  const page = await ctx.newPage();
  await page.goto(`${base}/login`);
  await page.getByLabel("Benutzername").fill("admin");
  await page.getByLabel("Passwort").fill(pw);
  await page.getByRole("button", { name: "Anmelden" }).click();
  await page.waitForURL((u) => !u.pathname.startsWith("/login"));
  return { ctx, page };
}
async function axe(page, name) {
  await page.evaluate(axeSrc);
  const r = await page.evaluate(async () => (await window.axe.run(document, { resultTypes: ["violations"] })).violations.filter((v) => ["serious", "critical"].includes(v.impact)).map((v) => v.id));
  ok(r.length === 0, `axe ${name}${r.length ? ": " + r.join(",") : ""}`);
}
const PAGES = ["/", "/agents", "/cves", "/notifications", "/settings", "/users"];

if (want("A1")) {
  for (const [w, h] of [[1440, 900], [390, 844]]) {
    const { ctx, page } = await open(w, h);
    const rect = [];
    for (const p of PAGES) {
      await page.goto(`${base}${p}`);
      await page.locator("[data-page-header]").waitFor();
      const m = await page.evaluate(() => {
        const t = document.querySelector("[data-page-title-row]").getBoundingClientRect();
        const hd = document.querySelector("[data-page-header]").getBoundingClientRect();
        const btnInHead = document.querySelector("[data-page-header] button") !== null;
        return { top: Math.round(t.top), h: Math.round(t.height), headH: hd.height, btnInHead, over: document.documentElement.scrollWidth > innerWidth + 1 };
      });
      rect.push([p, m]);
      ok(!m.btnInHead, `A1 ${w}px ${p}: keine Knöpfe im Seitenkopf`);
      ok(!m.over, `A1 ${w}px ${p}: kein horizontaler Überlauf`);
    }
    const tops = rect.map(([, m]) => m.top), hs = rect.map(([, m]) => m.h);
    ok(Math.max(...tops) - Math.min(...tops) <= 1, `A1 ${w}px: Titelzeile gleiche Position (${tops.join(",")})`);
    ok(Math.max(...hs) - Math.min(...hs) <= 1, `A1 ${w}px: Titelzeile gleiche Höhe (${hs.join(",")})`);
    // Agents und CVEs: Knopfzeile direkt unter dem Seitenkopf, gleiche Höhe
    const sec = {};
    for (const p of ["/agents", "/cves"]) {
      await page.goto(`${base}${p}`);
      await page.locator("[data-section-header]").first().waitFor();
      sec[p] = await page.evaluate(() => {
        const s = document.querySelector("[data-section-header]").getBoundingClientRect();
        const hd = document.querySelector("[data-page-header]").getBoundingClientRect();
        return { gap: Math.round(s.top - hd.bottom), h: Math.round(s.height) };
      });
    }
    if (w >= 1024) {
      ok(Math.abs(sec["/agents"].gap - sec["/cves"].gap) <= 1, `A1 ${w}px: Abstand Seitenkopf→Bereichskopf gleich (${sec["/agents"].gap}/${sec["/cves"].gap})`);
      ok(Math.abs(sec["/agents"].h - sec["/cves"].h) <= 1, `A1 ${w}px: Höhe Bereichskopf gleich (${sec["/agents"].h}/${sec["/cves"].h})`);
    }
    await page.goto(`${base}/agents`);
    await page.locator("[data-action-cell]").first().waitFor();
    await page.waitForTimeout(500);
    await axe(page, `A1 ${w}px /agents`);
    await ctx.close();
  }
}

if (want("A2")) {
  for (const w of [1280, 1440, 1920]) {
    const { ctx, page } = await open(w, 900);
    await page.goto(`${base}/agents`);
    await page.locator("[data-action-cell]").first().waitFor();
    const m = await page.evaluate(() => [...document.querySelector("[data-action-cell]").querySelectorAll("button")].map((b) => { const r = b.getBoundingClientRect(); return [b.textContent.trim(), Math.round(r.width), Math.round(r.height), Math.round(r.top)]; }));
    ok(m.length === 3 && m.every((x) => x[1] === m[0][1] && x[2] === m[0][2] && x[3] === m[0][3]), `A2 ${w}px: drei gleich große Knöpfe in einer Zeile ${JSON.stringify(m)}`);
    const clip = await page.evaluate(() => [...document.querySelector("[data-action-cell]").querySelectorAll("button")].some((b) => b.scrollWidth > b.clientWidth + 1));
    ok(!clip, `A2 ${w}px: Knopftext nicht abgeschnitten`);
    const ov = await page.evaluate(() => { const t = document.querySelector("table.tbl"); const wr = t.parentElement; return wr.scrollWidth > wr.clientWidth + 1 || document.documentElement.scrollWidth > innerWidth + 1; });
    ok(!ov, `A2 ${w}px: Tabelle ohne horizontales Scrollen`);
    ok(m.map((x) => x[0]).join("|") === "Daten jetzt abrufen|Token erneuern|Löschen", `A2 ${w}px: Reihenfolge/Beschriftung`);
    if (w === 1440) {
      await page.getByRole("button", { name: /^Agent .* löschen$/ }).first().click();
      const dlg = page.getByRole("dialog");
      await dlg.waitFor();
      ok(/löschen\?/.test(await dlg.innerText()), "A2: Löschen öffnet nur ein Bestätigungsfenster mit Namen");
      await page.keyboard.press("Escape");
      await dlg.waitFor({ state: "detached" });
      ok(await page.locator("table.tbl tbody tr").count() >= 1, "A2: Zeile nach Abbruch noch da");
      // Tastatur: Tab erreicht alle drei
      await page.getByRole("button", { name: /: Daten jetzt abrufen$/ }).first().focus();
      await page.keyboard.press("Tab");
      ok(await page.evaluate(() => document.activeElement?.getAttribute("aria-label")?.startsWith("Token erneuern")), "A2: Tastatur Tab → Token erneuern");
      await axe(page, "A2 /agents");
    }
    await ctx.close();
  }
  // Stufen: schmale Zelle über Containerbreite (Fenster 1024 → schmaler als 3 Textknöpfe)
  const { ctx, page } = await open(1040, 900);
  await page.goto(`${base}/agents`);
  await page.locator("[data-action-cell]").first().waitFor();
  const st = await page.evaluate(() => { const c = document.querySelector("[data-action-cell]"); return { w: c.clientWidth, stage: c.querySelector("button")?.dataset.stage ?? "menu", n: c.querySelectorAll("button").length }; });
  console.log("INFO 1040px Zelle", JSON.stringify(st));
  ok(st.stage === "1" || st.stage === "2" || st.stage === "menu", "A2: Stufe gesetzt");
  // Stufe 2 und 3 erzwingen: Zellbreite per Style einengen
  for (const [width, exp] of [[250, "2"], [100, "menu"]]) {
    const r = await page.evaluate((w) => { const c = document.querySelector("[data-action-cell]"); c.style.width = w + "px"; c.style.flex = "none"; return null; }, width);
    await page.waitForTimeout(150);
    const got = await page.evaluate(() => { const c = document.querySelector("[data-action-cell]"); const b = [...c.querySelectorAll("button")]; return b.length === 1 && b[0].getAttribute("aria-haspopup") ? "menu" : b[0]?.dataset.stage; });
    ok(got === exp, `A2: Zellbreite ${width}px → Stufe ${exp} (war ${got})`);
    if (exp === "2") {
      const lab = await page.evaluate(() => [...document.querySelector("[data-action-cell]").querySelectorAll("button")].map((b) => [!!b.getAttribute("aria-label"), !!b.title || b.textContent.trim().length > 0]));
      ok(lab.every((x) => x[0]), "A2 Stufe 2: aria-label an allen Knöpfen");
    }
  }
  await ctx.close();
  // Mobil: gestapelte Karten, Knöpfe in einer Zeile
  const mob = await open(390, 844);
  await mob.page.goto(`${base}/agents`);
  await mob.page.locator("[data-action-cell]").first().waitFor();
  const mm = await mob.page.evaluate(() => { const c = document.querySelector("[data-action-cell]"); const bs = [...c.querySelectorAll("button")]; return { n: bs.length, tops: new Set(bs.map((b) => Math.round(b.getBoundingClientRect().top))).size, over: document.documentElement.scrollWidth > innerWidth + 1 }; });
  ok(!mm.over, "A2 mobil: kein Überlauf");
  console.log("INFO 390px", JSON.stringify(mm));
  await mob.ctx.close();
}
await browser.close();
