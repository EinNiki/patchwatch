// Bildraten-Messung (rAF-Abstände) für Navigation, Dialog, Stern und Scrollen der 100-Zeilen-Liste, optional mit gedrosselter CPU.
//   PW_MODULE=… PW_CHROME=… PW_PASSWORD=… PW_BASE=… CPU=4 WIDTH=1920 node scripts/fps.mjs
import { createRequire } from "node:module";
const { chromium } = createRequire(import.meta.url)(process.env.PW_MODULE ?? "playwright");
const base = (process.env.PW_BASE ?? "http://127.0.0.1:3200").replace(/\/$/, "");
const cpu = Number(process.env.CPU ?? 1);
const width = Number(process.env.WIDTH ?? 1920);
const b = await chromium.launch({ executablePath: process.env.PW_CHROME, args: ["--no-sandbox"] });
const ctx = await b.newContext({ viewport: { width, height: Math.round(width * 0.5625) } });
const page = await ctx.newPage();
await page.goto(`${base}/login`);
await page.getByLabel("Benutzername").fill("admin");
await page.getByLabel("Passwort").fill(process.env.PW_PASSWORD);
await page.getByRole("button", { name: "Anmelden" }).click();
await page.waitForURL((u) => !u.pathname.startsWith("/login"));
await page.locator("tbody tr").first().waitFor();
const cdp = await ctx.newCDPSession(page);
if (cpu > 1) await cdp.send("Emulation.setCPUThrottlingRate", { rate: cpu });
await page.evaluate(() => {
  window.__frames = [];
  let last = performance.now();
  const tick = (t) => { window.__frames.push(t - last); last = t; requestAnimationFrame(tick); };
  requestAnimationFrame(tick);
});
const mark = async (label, fn) => {
  await page.evaluate(() => (window.__frames.length = 0));
  await fn();
  await page.waitForTimeout(400);
  const f = await page.evaluate(() => window.__frames.slice());
  const sorted = [...f].sort((a, c) => a - c);
  const q = (p) => Math.round(sorted[Math.min(sorted.length - 1, Math.floor(p * sorted.length))] * 10) / 10;
  console.log(`${label.padEnd(34)} Frames ${String(f.length).padStart(3)}  p50 ${q(0.5)} ms  p95 ${q(0.95)} ms  max ${q(1)} ms  >33 ms: ${f.filter((x) => x > 33.4).length}  >50 ms: ${f.filter((x) => x > 50).length}`);
};
const nav = (n) => async () => { await page.getByRole("link", { name: n, exact: true }).first().click(); await page.waitForTimeout(500); };
console.log(`CPU ${cpu}x, ${width} px, ${base}`);
await mark("Navigation Hosts→CVEs", nav("CVEs"));
await page.locator("tr:has(.star-btn)").nth(40).waitFor();
await mark("Scrollen CVE-Liste (100 Zeilen)", async () => { for (let i = 0; i < 25; i++) { await page.mouse.move(700, 500); await page.mouse.wheel(0, 220); await page.waitForTimeout(30); } });
await page.evaluate(() => window.scrollTo(0, 0));
await mark("Stern umschalten", async () => { await page.locator("tr:has(.star-btn) .star-btn").nth(6).click(); await page.waitForTimeout(300); await page.locator("tr:has(.star-btn) .star-btn").nth(6).click(); });
await mark("Navigation CVEs→Agents", nav("Agents"));
await mark("Dialog öffnen/schließen", async () => { await page.getByRole("button", { name: "Agent hinzufügen" }).click(); await page.waitForTimeout(400); await page.keyboard.press("Escape"); });
await mark("Navigation Agents→Hosts", nav("Hosts"));
await mark("Navigation Hosts→Einstellungen", nav("Einstellungen"));
await b.close();
