// E2E: Seitenleiste (gleitende Fläche, Einklappen mit Gedächtnis, Icon-Rail, Off-Canvas mit Fokusfalle, Tooltips, Zähler).
//   PW_MODULE=… PW_CHROME=… PW_PWFILE=<Datei mit Admin-Passwort> [SHOTS=<Ordner>] node scripts/e2e-sidebar.mjs
// Mit SHOTS werden Bilder (390, 768, 1440, 1920 px; hell und dunkel) dorthin geschrieben. Es werden keine Daten verändert.
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
const { chromium } = createRequire(import.meta.url)(process.env.PW_MODULE);
const pw = readFileSync(process.env.PW_PWFILE, "utf8").trim();
const base = process.env.PW_BASE ?? "http://127.0.0.1:3100";
const ok = (c, m) => { console.log(c ? "OK  " : "FAIL", m); if (!c) process.exitCode = 1; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const browser = await chromium.launch({ executablePath: process.env.PW_CHROME, args: ["--no-sandbox"] });
const login = await browser.newContext({ viewport: { width: 1440, height: 900 } });
{
  const p = await login.newPage();
  await p.goto(`${base}/login`);
  await p.getByLabel("Benutzername").fill("admin");
  await p.getByLabel("Passwort").fill(pw);
  await p.getByRole("button", { name: "Anmelden" }).click();
  await p.waitForURL((u) => !u.pathname.startsWith("/login"));
}
const state = await login.storageState();
await login.close();

async function page(opts = {}) {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, storageState: state, colorScheme: process.env.SCHEME ?? "light", ...opts });
  return { ctx, p: await ctx.newPage() };
}
const css = (loc, prop) => loc.evaluate((e, p) => getComputedStyle(e).getPropertyValue(p), prop);
const widthOf = (loc) => loc.evaluate((e) => Math.round(e.getBoundingClientRect().width));
const tf = (p) => p.locator("aside [data-glide]").evaluate((e) => getComputedStyle(e).transform);

try {
  // ---- Breit (1440): Fläche gleitet, Einklappen, Gedächtnis ----
  let { ctx, p } = await page();
  await p.goto(`${base}/agents`);
  const aside = p.locator("aside#sidebar");
  ok((await widthOf(aside)) === 221 || (await widthOf(aside)) === 220, "ausgeklappt 220 px breit");
  ok((await p.locator('aside a[aria-current="page"]').innerText()).includes("Agents"), "aktive Zeile hat aria-current=page");
  const glide = p.locator("aside [data-glide]");
  ok((await css(glide, "transition-property")) === "transform, opacity", "Fläche animiert nur transform (und opacity zum Ein-/Ausblenden)");
  ok((await css(glide, "transition-duration")).startsWith("0.2s"), "Gleitdauer 200 ms");
  const before = await tf(p);
  await p.locator("aside").getByRole("link", { name: "Hosts", exact: true }).click();
  await p.waitForURL(`${base}/`);
  await sleep(60);
  const mid = await tf(p);
  await sleep(400);
  const end = await tf(p);
  ok(before !== end && mid !== before && mid !== end, `Fläche gleitet (Start ${before}, Mitte ${mid}, Ende ${end})`);
  const linkBox = await p.locator('aside a[aria-current="page"]').boundingBox();
  const navBox = await p.locator("aside nav").boundingBox();
  ok(Math.abs(end.match(/-?[\d.]+/g)[5] - (linkBox.y - navBox.y)) < 1.5, "Endposition liegt auf der aktiven Zeile");

  const hide = p.getByRole("button", { name: "Seitenleiste ausblenden" });
  ok(await hide.isVisible(), "Schaltfläche „Seitenleiste ausblenden“ sichtbar");
  ok((await css(aside, "transition-duration")).startsWith("0.24s") && (await css(aside, "transition-property")) === "width", "Breite animiert in 240 ms");
  await hide.click();
  await sleep(400);
  ok((await widthOf(aside)) === 56, "eingeklappt 56 px breit");
  ok((await p.locator("main").evaluate((e) => parseFloat(getComputedStyle(e).paddingLeft))) === 56, "Inhalt rückt nach (padding-left 56 px)");
  const lab = p.locator("aside nav a", { hasText: "Hosts" }).locator("span").nth(1);
  ok((await css(lab, "opacity")) === "0" && (await css(lab, "transition-duration")).startsWith("0.12s"), "Beschriftung blendet in 120 ms aus");
  ok(await p.getByRole("button", { name: "Seitenleiste einblenden" }).evaluate((e) => e === document.activeElement), "Fokus wandert auf „Einblenden“");
  ok(await p.getByRole("link", { name: /^Hosts/ }).first().isVisible(), "Name bleibt für Screenreader im Link (Rail)");
  ok((await p.evaluate(() => localStorage.getItem("pw-nav:collapsed"))) === "1", "Zustand in localStorage");
  await p.reload();
  ok((await p.evaluate(() => document.documentElement.getAttribute("data-sb"))) === "collapsed", "nach Neuladen weiter eingeklappt");
  ok((await widthOf(p.locator("aside#sidebar"))) === 56, "kein Aufblitzen: 56 px direkt nach dem Laden");
  // Tooltip bei Tastaturfokus in der Rail
  await p.keyboard.press("Tab");
  await p.locator("aside nav a").first().focus();
  await sleep(250);
  ok((await css(p.locator("aside nav a").first().locator("xpath=..").locator('span[aria-hidden="true"]').last(), "opacity")) === "1", "Tooltip bei Fokus sichtbar");
  const ring = await p.locator("aside nav a").first().evaluate((e) => { e.focus(); return getComputedStyle(e).outlineStyle; });
  ok(ring !== "none", "Fokusring sichtbar");
  if (process.env.SHOTS) await p.screenshot({ path: `${process.env.SHOTS}/side-1440-collapsed.png` });
  await p.getByRole("button", { name: "Seitenleiste einblenden" }).click();
  await sleep(400);
  ok((await widthOf(p.locator("aside#sidebar"))) === 220, "wieder eingeblendet");
  ok(await p.getByRole("button", { name: "Seitenleiste ausblenden" }).evaluate((e) => e === document.activeElement), "Fokus wandert auf „Ausblenden“");
  // Zähler
  const hostsLink = p.locator("aside nav a", { hasText: "Hosts" });
  const badge = hostsLink.locator("xpath=..").locator("span.sr-only");
  ok(/kritischem Stand/.test(await badge.first().innerText().catch(() => "")), "Zähler Hosts mit Text für Screenreader");
  // Untergruppe mit Führungslinie
  await p.goto(`${base}/notifications/ntfy`);
  await sleep(300);
  ok((await p.locator('aside a[aria-current="page"]').innerText()).includes("ntfy"), "Unterseite aktiv markiert");
  if (process.env.SHOTS) await p.screenshot({ path: `${process.env.SHOTS}/side-1440-notif.png` });
  if (process.env.SHOTS) {
    await p.setViewportSize({ width: 1920, height: 1000 });
    await sleep(300);
    await p.screenshot({ path: `${process.env.SHOTS}/side-1920.png` });
  }
  await ctx.close();

  // ---- Reduzierte Bewegung ----
  ({ ctx, p } = await page({ reducedMotion: "reduce" }));
  await p.goto(`${base}/agents`);
  const d = await css(p.locator("aside [data-glide]"), "transition-duration");
  ok(d.split(",").every((x) => parseFloat(x) <= 0.001), `reduzierte Bewegung: Gleiten ohne Übergang (${d})`);
  await ctx.close();

  // ---- Rail (768 px): immer schmal, keine Ausblenden-Schaltfläche ----
  ({ ctx, p } = await page({ viewport: { width: 800, height: 900 } }));
  await p.goto(`${base}/cves`);
  ok((await widthOf(p.locator("aside#sidebar"))) === 56, "768–1023 px: Icon-Rail");
  ok(!(await p.getByRole("button", { name: "Seitenleiste ausblenden" }).isVisible()), "in der Rail keine Ausblenden-Schaltfläche");
  if (process.env.SHOTS) await p.screenshot({ path: `${process.env.SHOTS}/side-800.png` });
  await ctx.close();

  // ---- Off-Canvas (390 px) ----
  ({ ctx, p } = await page({ viewport: { width: 390, height: 800 } }));
  await p.goto(`${base}/agents`);
  const menu = p.getByRole("button", { name: "Menü", exact: true });
  await menu.click();
  const dlg = p.getByRole("dialog", { name: "Navigation" });
  await dlg.waitFor();
  await p.waitForFunction(() => document.querySelector("#mobile-menu")?.contains(document.activeElement), null, { timeout: 2000 }).catch(() => {});
  ok(await dlg.evaluate((e) => e.contains(document.activeElement)), "Off-Canvas: Fokus im Menü");
  ok((await dlg.locator("nav a", { hasText: "Hosts" }).locator("span").nth(1).evaluate((e) => getComputedStyle(e).opacity)) === "1", "Off-Canvas zeigt immer Beschriftungen");
  for (let i = 0; i < 25; i++) await p.keyboard.press("Tab");
  ok(await dlg.evaluate((e) => e.contains(document.activeElement)), "Tab bleibt im Menü (Fokusfalle)");
  for (let i = 0; i < 25; i++) await p.keyboard.press("Shift+Tab");
  ok(await dlg.evaluate((e) => e.contains(document.activeElement)), "Shift+Tab bleibt im Menü");
  if (process.env.SHOTS) await p.screenshot({ path: `${process.env.SHOTS}/side-390-open.png` });
  await p.keyboard.press("Escape");
  await sleep(300);
  ok(await menu.evaluate((e) => e === document.activeElement), "Esc schließt, Fokus kehrt zum Menü-Knopf zurück");
  await ctx.close();
} finally {
  await browser.close();
}
