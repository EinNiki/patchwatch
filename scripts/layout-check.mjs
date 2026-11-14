// Layout-Prüfung: kein horizontaler Seitenüberlauf, fester Tabellenkopf, Trefferflächen < 768 px.
// Aufruf (Dev-Stack läuft, siehe scripts/screenshots.mjs für die Umgebung):
//   PW_MODULE=… PW_CHROME=… PW_PASSWORD=… node scripts/layout-check.mjs
// Umgebung: PW_BASE (Standard http://127.0.0.1:3100), PW_USER (admin), PW_WIDTHS (Standard 390,480,720,768,1024,1440,1920),
// PW_SCHEMES (Standard dark,light), PW_ONLY (Kommaliste von Seitennamen). Exit 1 bei Verstößen.
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";

const base = (process.env.PW_BASE ?? "http://127.0.0.1:3100").replace(/\/$/, "");
const user = process.env.PW_USER ?? "admin";
const password = process.env.PW_PASSWORD ?? (process.env.PW_PWFILE ? readFileSync(process.env.PW_PWFILE, "utf8").trim() : (console.error("PW_PASSWORD oder PW_PWFILE setzen"), process.exit(1)));
const { chromium } = createRequire(import.meta.url)(process.env.PW_MODULE ?? "playwright");
const widths = (process.env.PW_WIDTHS ?? "390,480,720,768,1024,1440,1920").split(",").map(Number);
const schemes = (process.env.PW_SCHEMES ?? "dark,light").split(",");
const PAGES = [
  ["hosts", "/"],
  ["host-detail", "/hosts/host:web-01"],
  ["host-debian", "/hosts/host:db-01"],
  ["host-proxmox", "/hosts/host:pve-01"],
  ["host-reboot", "/hosts/host:db-02?cve=reboot"],
  ["cves", "/cves"],
  ["cve-detail", "/cves/CVE-2024-1086"],
  ["agents", "/agents"],
  ["notifications", "/notifications"],
  ["notification-ntfy", "/notifications/ntfy"],
  ["settings", "/settings"],
];

const only = process.env.PW_ONLY?.split(",");
if (only) PAGES.splice(0, PAGES.length, ...PAGES.filter(([n]) => only.includes(n)));
const failures = [];
const fail = (page, w, scheme, msg) => failures.push(`${page} @${w} ${scheme}: ${msg}`);

/** Im Browser: sichtbare Bedienelemente unter 44 px (Höhe oder Breite). Fließtext-Links und sr-only sind ausgenommen. */
function smallTargets(root) {
  const out = [];
  const els = document.querySelectorAll(root + " a[href], " + root + " button, " + root + " select, " + root + " input, " + root + " summary");
  for (const el of els) {
    if (el.type === "hidden" || el.closest("thead") || el.closest("[inert]") || el.getAttribute("aria-hidden") === "true") continue;
    const target = el.matches("input[type=checkbox], input[type=radio]") ? (el.closest("label") ?? el) : el;
    const cs = getComputedStyle(target);
    if (cs.display === "inline" && target.tagName === "A") continue; // Link im Fließtext
    const r = target.getBoundingClientRect();
    if (r.width === 0 || r.height === 0 || cs.visibility === "hidden") continue;
    if (r.width <= 1 || r.height <= 1) continue; // sr-only
    // Höhe ≥ 44 px; kurze Links dürfen schmaler sein (≥ 24 px, WCAG 2.5.8), Schaltflächen und Felder nicht.
    const minW = target.tagName === "A" ? 24 : 43.5;
    if (r.height < 43.5 || r.width < minW) out.push(`${target.tagName.toLowerCase()} "${(target.getAttribute("aria-label") || target.textContent || "").trim().slice(0, 40)}" ${Math.round(r.width)}x${Math.round(r.height)}`);
  }
  return out;
}

const browser = await chromium.launch({ executablePath: process.env.PW_CHROME, args: ["--no-sandbox"] });
let checks = 0;
// Einmal anmelden (das Login-Limit liegt bei 10 Versuchen je 10 Minuten) und die Sitzung für alle Kontexte wiederverwenden.
const loginCtx = await browser.newContext();
const loginPage = await loginCtx.newPage();
await loginPage.goto(`${base}/login`);
await loginPage.getByLabel("Benutzername").fill(user);
await loginPage.getByLabel("Passwort").fill(password);
await loginPage.getByRole("button", { name: "Anmelden", exact: true }).click();
await loginPage.waitForURL((u) => !u.pathname.startsWith("/login"));
const storageState = await loginCtx.storageState();
await loginCtx.close();
for (const scheme of schemes) {
  for (const w of widths) {
    const ctx = await browser.newContext({ viewport: { width: w, height: 900 }, colorScheme: scheme, reducedMotion: "reduce", storageState });
    const page = await ctx.newPage();
    await page.goto(base + "/");
    await page.waitForLoadState("networkidle");
    const ids = Object.fromEntries(await page.evaluate(async () => (await (await fetch("/api/v1/hosts")).json()).map((h) => [h.name, h.id])));

    for (const [name, path] of PAGES) {
      await page.goto(base + path.replace(/host:([\w.-]+)/, (_, n) => ids[n]));
      await page.waitForLoadState("networkidle");
      await page.waitForTimeout(400);
      checks++;
      const over = await page.evaluate(() => ({ sw: document.documentElement.scrollWidth, iw: window.innerWidth }));
      if (over.sw > over.iw) fail(name, w, scheme, `Seitenüberlauf scrollWidth ${over.sw} > ${over.iw}`);

      // Fester Tabellenkopf (ab 768 px; darunter ist der Kopf ausgeblendet). Nur bei Tabellen, die lang genug zum Scrollen sind.
      if (w >= 1024) {
        const info = await page.evaluate(() => {
          const t = document.querySelector("table.tbl");
          if (!t) return null;
          const r = t.getBoundingClientRect();
          // Liegt die Tabelle in einem horizontalen Scrollbehälter (schmale Fenster), kann der Kopf dort konstruktionsbedingt nicht fest sein.
          const wrapped = [...(function* () { for (let e = t.parentElement; e && e !== document.body; e = e.parentElement) yield e; })()].some((e) => /auto|scroll/.test(getComputedStyle(e).overflowX));
          return { top: r.top + window.scrollY, h: r.height, page: document.documentElement.scrollHeight, wrapped };
        });
        // Nur prüfen, wenn die Seite so weit scrollen kann; sonst klemmt der Browser das Scrollen und der Kopf steht legitim tiefer.
        if (info && !info.wrapped && info.h > 700 && info.page - 900 >= info.top + 300) {
          await page.evaluate((y) => window.scrollTo(0, y + 300), info.top);
          await page.waitForTimeout(150);
          const th = await page.evaluate(() => Math.round(document.querySelector("table.tbl th")?.getBoundingClientRect().top ?? -999));
          if (Math.abs(th) > 1) fail(name, w, scheme, `Tabellenkopf nicht fest (top ${th})`);
        }
      }

      // Host-Detail: Satz, Balken, Kacheln und eine aktive Liste. Ab 1440 px sind Kopf, Kacheln und ≥ 10 Zeilen der
      // aktiven Liste ohne Seitenscroll sichtbar; auf allen Breiten genau eine Liste, keine Tabs, Kacheln vorhanden.
      if (name === "host-detail" || name === "host-debian" || name === "host-reboot") {
        const cve = await page.evaluate(() => {
          const tiles = document.querySelector('[aria-label="CVE-Zustände"]');
          const lists = [...document.querySelectorAll('[role=region][aria-label$=", Liste"]')];
          const visibleRows = (l) => [...l.querySelectorAll("li")].filter((li) => li.getBoundingClientRect().bottom <= window.innerHeight).length;
          return {
            tiles: tiles ? Math.round(tiles.getBoundingClientRect().bottom) : null,
            tileButtons: tiles ? tiles.querySelectorAll("button").length : 0,
            sentence: Boolean(document.querySelector("main p[aria-live=polite]")?.textContent?.trim()),
            bar: Boolean(document.querySelector('main [role=img][aria-label^="Verteilung"]')),
            lists: lists.length,
            totals: lists.map((l) => l.querySelectorAll("li").length),
            rows: lists.map(visibleRows),
            tabs: document.querySelectorAll('[role=tablist][aria-label="CVE-Ansicht"] [role=tab]').length,
            pressed: document.querySelectorAll('[aria-label="CVE-Zustände"] [aria-pressed=true], main button[aria-pressed=true]').length,
            ih: window.innerHeight,
          };
        });
        if (cve.tiles === null) fail(name, w, scheme, "CVE-Kacheln fehlen");
        else {
          if (cve.tileButtons < 3) fail(name, w, scheme, `erwartet 3 Kacheln, gefunden ${cve.tileButtons}`);
          if (!cve.sentence) fail(name, w, scheme, "Zusammenfassungssatz fehlt");
          if (!cve.bar) fail(name, w, scheme, "Balken fehlt");
          if (cve.lists !== 1) fail(name, w, scheme, `genau eine aktive CVE-Liste erwartet, gefunden ${cve.lists}`);
          if (cve.tabs > 0) fail(name, w, scheme, "Tabs nicht erwartet");
          if (cve.pressed < 1) fail(name, w, scheme, "keine Kachel als aktiv markiert");
          if (w >= 1440) {
            if (cve.tiles > cve.ih) fail(name, w, scheme, "Kacheln nicht ohne Seitenscroll sichtbar");
            cve.rows.forEach((n, i) => {
              if (n < Math.min(10, cve.totals[i])) fail(name, w, scheme, `nur ${n} CVE-Zeilen ohne Seitenscroll sichtbar (≥ 10 erwartet)`);
            });
          }
        }
      }

      if (w < 768) {
        const small = await page.evaluate(smallTargets, "main");
        for (const s of small) fail(name, w, scheme, `Trefferfläche < 44 px: ${s}`);
      }
    }

    if (w < 768) {
      await page.goto(base + "/");
      await page.getByRole("button", { name: "Menü", exact: true }).click();
      await page.waitForTimeout(300);
      const over = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
      if (over > 0) fail("menu", w, scheme, `Seitenüberlauf bei offenem Menü (+${over})`);
      for (const s of await page.evaluate(smallTargets, "#mobile-menu")) fail("menu", w, scheme, `Trefferfläche < 44 px: ${s}`);
      checks++;
    }
    await ctx.close();
  }
}
await browser.close();
console.log(`${checks} Prüfungen, ${failures.length} Verstöße`);
for (const f of failures) console.log("  " + f);
process.exit(failures.length ? 1 : 0);
