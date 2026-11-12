// E2E: Profilbild (Initialen, eingeklappte Seitenleiste, Upload gültig/ungültig, Entfernen, Header, kein Zugriff ohne Login).
// Schreibt ein Profilbild in die Datenbank des laufenden Servers: nur gegen eine Wegwerf-Datenbank ausführen.
//   PW_MODULE=… PW_CHROME=… PW_PWFILE=<Datei mit Admin-Passwort> [PW_SHOTS=<Ordner>] node scripts/e2e-avatar.mjs
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { deflateSync } from "node:zlib";
const { chromium, request } = createRequire(import.meta.url)(process.env.PW_MODULE);
const pw = readFileSync(process.env.PW_PWFILE, "utf8").trim();
const base = process.env.PW_BASE ?? "http://127.0.0.1:3100";
const shots = process.env.PW_SHOTS;
const ok = (c, m) => { console.log(c ? "OK  " : "FAIL", m); if (!c) process.exitCode = 1; };

// Kleiner PNG-Kodierer (RGB, Farbverlauf), damit der Test ohne Bilddatei im Repository auskommt.
function crc32(b) { let c = ~0; for (const x of b) { c ^= x; for (let k = 0; k < 8; k++) c = c & 1 ? (c >>> 1) ^ 0xedb88320 : c >>> 1; } return ~c >>> 0; }
function png(w, h) {
  const raw = Buffer.alloc((w * 3 + 1) * h);
  for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) { const o = y * (w * 3 + 1); raw[o] = 0; raw[o + 1 + x * 3] = (x * 255 / w) | 0; raw[o + 2 + x * 3] = (y * 255 / h) | 0; raw[o + 3 + x * 3] = 120; }
  const chunk = (t, d) => { const b = Buffer.alloc(12 + d.length); b.writeUInt32BE(d.length, 0); b.write(t, 4); d.copy(b, 8); b.writeUInt32BE(crc32(b.subarray(4, 8 + d.length)), 8 + d.length); return b; };
  const ih = Buffer.alloc(13); ih.writeUInt32BE(w, 0); ih.writeUInt32BE(h, 4); ih[8] = 8; ih[9] = 2;
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk("IHDR", ih), chunk("IDAT", deflateSync(raw)), chunk("IEND", Buffer.alloc(0))]);
}
const contrast = (a, b) => { const l = (c) => { const v = c.map((x) => x / 255).map((x) => (x <= 0.03928 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4)); return 0.2126 * v[0] + 0.7152 * v[1] + 0.0722 * v[2]; }; const [x, y] = [l(a), l(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); };

const browser = await chromium.launch({ executablePath: process.env.PW_CHROME, args: ["--no-sandbox"] });
try {
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await ctx.newPage();
  await page.goto(`${base}/login`);
  await page.getByLabel("Benutzername").fill("admin");
  await page.getByLabel("Passwort").fill(pw);
  await page.getByRole("button", { name: "Anmelden" }).click();
  await page.waitForURL((u) => !u.pathname.startsWith("/login"));
  // Ausgangslage: kein eigenes Bild (Wegwerf-Datenbank).
  await page.evaluate(async () => { const me = await (await fetch("/api/v1/auth/me")).json(); await fetch("/api/v1/auth/avatar", { method: "DELETE", headers: { "x-csrf-token": me.csrf_token } }); });
  await page.goto(`${base}/settings`);
  const dot = page.locator('[title="admin"]:visible span[aria-hidden="true"]').first();
  await dot.waitFor();

  // Initialen, Größe, Kontrast in beiden Modi.
  ok((await dot.innerText()) === "A", "Initialen „A“ für „admin“");
  const box = await dot.boundingBox();
  ok(Math.round(box.width) === 20 && Math.round(box.height) === 20, `Kreis 20 px (Seitenleiste, Raster der Navigation) (${box.width}×${box.height})`);
  for (const scheme of ["light", "dark"]) {
    await page.emulateMedia({ colorScheme: scheme });
    const [bg, fg] = await dot.evaluate((e) => { const s = getComputedStyle(e); const p = (c) => c.match(/\d+(\.\d+)?/g).slice(0, 3).map(Number); return [p(s.backgroundColor), p(s.color)]; });
    ok(contrast(bg, fg) >= 4.5, `Kontrast Initialen ${scheme}: ${contrast(bg, fg).toFixed(2)}:1`);
  }
  await page.emulateMedia({ colorScheme: "dark" });

  // Eingeklappt: nur das Bild, Name als Tooltip (und für Screenreader).
  await page.getByRole("button", { name: /Seitenleiste ausblenden/ }).click();
  await page.waitForTimeout(400);
  const nameVisible = await page.locator('[title="admin"]:visible p').first().evaluate((p) => { const r = p.getBoundingClientRect(); return r.width > 2 && r.height > 2 && getComputedStyle(p).position !== "absolute"; });
  ok(await dot.isVisible() && !nameVisible, "eingeklappt: nur das Bild, Name nicht sichtbar");
  await dot.hover();
  ok(await page.getByText("admin", { exact: true }).filter({ visible: true }).count() >= 1, "eingeklappt: Tooltip mit dem Namen");
  if (shots) await page.screenshot({ path: `${shots}/avatar-collapsed-dark.png`, clip: { x: 0, y: 700, width: 120, height: 200 } });
  await page.getByRole("button", { name: /Seitenleiste einblenden/ }).click();
  await page.waitForTimeout(300);

  // Ungültige Dateien: Meldung, nichts gespeichert.
  const file = page.locator('input[type="file"]');
  const err = page.locator("p[role=alert]");
  const bad = async (name, mime, buf, re, label) => {
    await file.setInputFiles({ name, mimeType: mime, buffer: buf });
    const hit = await err.filter({ hasText: re }).waitFor({ timeout: 5000 }).then(() => true, () => false);
    ok(hit, `${label}: ${(await err.allInnerTexts()).join(" ").replace(/\s+/g, " ").slice(0, 70)}`);
  };
  await bad("bild.png", "image/png", Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script>1</script></svg>'), /PNG, JPEG und WebP/, "SVG mit falscher Endung .png");
  await bad("anim.gif", "image/gif", Buffer.from("GIF89a\x01\x00\x01\x00\x00\x00\x00;"), /kein GIF/, "GIF");
  await bad("gross.png", "image/png", Buffer.concat([png(8, 8).subarray(0, 40), Buffer.alloc(2.2 * 1024 * 1024)]), /2 MB/, "zu groß (2,2 MB)");
  await bad("kaputt.png", "image/png", Buffer.concat([png(8, 8).subarray(0, 8), Buffer.from("kein bild")]), /nicht als Bild lesen/, "kaputte Datei");
  ok((await page.locator('img[src*="/auth/avatar"]').count()) === 0, "nach Fehlern kein Bild gespeichert");

  // Gültig: Vorschau, Speichern, Bild in der Seitenleiste.
  await file.setInputFiles({ name: "foto.png", mimeType: "image/png", buffer: png(300, 200) });
  await page.getByRole("img", { name: "Vorschau des Ausschnitts" }).waitFor();
  if (shots) await page.screenshot({ path: `${shots}/avatar-crop.png` });
  await page.getByRole("button", { name: "Speichern" }).first().click();
  const img = page.locator('[title="admin"]:visible img');
  await img.waitFor();
  await page.waitForFunction(() => [...document.querySelectorAll('[title="admin"] img')].some((i) => i.complete && i.naturalWidth > 0 && i.offsetParent !== null));
  ok((await img.getAttribute("alt")) === "", "Bild ist dekorativ (alt=\"\")");
  ok((await img.evaluate((i) => i.naturalWidth)) === 128, "gespeichertes Bild ist 128 px breit");
  const src = await img.getAttribute("src");
  ok(/^\/api\/v1\/auth\/avatar\?v=\d+$/.test(src), `Bild kommt nur von der eigenen API (${src})`);
  const res = await page.request.get(`${base}/api/v1/auth/avatar`);
  const h = res.headers();
  ok(res.status() === 200 && /^image\/(webp|png)$/.test(h["content-type"]) && h["x-content-type-options"] === "nosniff" && h["content-security-policy"] === "default-src 'none'" && h["cache-control"].startsWith("private"), `Header: ${h["content-type"]}, nosniff, CSP, ${h["cache-control"]}`);
  ok((await res.body()).length <= 64 * 1024, `Größe ${(await res.body()).length} Bytes ≤ 64 KB`);
  if (shots) await page.screenshot({ path: `${shots}/avatar-1440-dark.png` });

  // Ohne Anmeldung kein Zugriff.
  const anon = await request.newContext();
  ok((await anon.get(`${base}/api/v1/auth/avatar`)).status() === 401, "ohne Anmeldung: 401");
  await anon.dispose();

  // Breiten und Schemata: Bild und Name sichtbar, Seitenleiste ohne Überlauf.
  for (const scheme of ["light", "dark"]) for (const w of [390, 768, 1440, 1920]) {
    await page.setViewportSize({ width: w, height: 900 });
    await page.emulateMedia({ colorScheme: scheme });
    await page.goto(`${base}/settings`);
    if (w < 768) await page.getByRole("button", { name: /Menü/ }).click();
    await img.waitFor();
    const r = await img.boundingBox();
    ok(r && Math.round(r.width) === 20 && (await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)) <= 0, `${scheme} ${w}px: Bild 20 px, kein Überlauf`);
    if (shots && (w === 390 || w === 1920)) await page.screenshot({ path: `${shots}/avatar-${w}-${scheme}.png` });
  }

  // Entfernen: zurück zu den Initialen.
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(`${base}/settings`);
  await page.getByRole("button", { name: "Entfernen" }).click();
  await dot.waitFor();
  ok((await page.locator('[title="admin"]:visible img').count()) === 0 && (await dot.innerText()) === "A", "Entfernen: wieder Initialen");
  ok((await page.request.get(`${base}/api/v1/auth/avatar`)).status() === 404, "Entfernen: API liefert 404");
  await ctx.close();
} finally {
  await browser.close();
}
