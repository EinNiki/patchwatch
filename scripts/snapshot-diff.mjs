// Vergleicht die laufende Web-UI pixelweise mit docs/design/snapshot-2026-11-11/screenshots/ (keine Abhängigkeit außer Playwright:
// der Vergleich läuft im Browser über ein Canvas). Seiten: Hosts, Host-Detail, CVEs, Agents, Einstellungen, Benachrichtigungen,
// Login; je 1440 und 390 px, hell und dunkel. Aufnahme wie in scripts/screenshots.mjs (reduzierte Bewegung, Höhe auf 950 px gekürzt).
//
//   PW_MODULE=… PW_CHROME=… PW_BASE=http://127.0.0.1:3300 PW_PWFILE=<Passwortdatei> node scripts/snapshot-diff.mjs [ergebnis.md]
//
// Umgebung: PW_TOL (Toleranz je Pixel als größte Kanalabweichung 0–255, Standard 24), PW_LIMIT (Schwelle in %, Standard 2),
// PW_DIFFDIR (Ordner für Differenzbilder; Standard keiner). Exit 1, wenn eine Seite über der Schwelle liegt: die Demo-Daten
// unterscheiden sich vom Snapshot (Seed-Zeitpunkt, CVE-Daten), Treffer sind daher zu deuten, nicht blind zu beheben.
import { createRequire } from "node:module";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const base = (process.env.PW_BASE ?? "http://127.0.0.1:3300").replace(/\/$/, "");
const user = process.env.PW_USER ?? "admin";
const password = process.env.PW_PASSWORD ?? (process.env.PW_PWFILE ? readFileSync(process.env.PW_PWFILE, "utf8").trim() : (console.error("PW_PASSWORD oder PW_PWFILE setzen"), process.exit(1)));
const { chromium } = createRequire(import.meta.url)(process.env.PW_MODULE ?? "playwright");
const tol = Number(process.env.PW_TOL ?? 24);
const limit = Number(process.env.PW_LIMIT ?? 2);
const diffDir = process.env.PW_DIFFDIR;
const snapDir = join(dirname(fileURLToPath(import.meta.url)), "..", "docs/design/snapshot-2026-11-11/screenshots");
const MAX_H = 950;
const PAGES = [
  ["hosts", "/"], ["host-detail", "/hosts/host:web-01"], ["cves", "/cves"], ["agents", "/agents"],
  ["settings", "/settings"], ["notifications", "/notifications"], ["login", "/login"],
];

/** Läuft im Browser: Anteil abweichender Pixel (%) zweier PNGs (base64); Pixel außerhalb der kleineren Fläche zählen als abweichend. */
async function compare([a64, b64, tolerance, wantDiff]) {
  const load = (b64) => new Promise((res, rej) => { const i = new Image(); i.onload = () => res(i); i.onerror = rej; i.src = "data:image/png;base64," + b64; });
  const [a, b] = await Promise.all([load(a64), load(b64)]);
  const W = Math.max(a.width, b.width), H = Math.max(a.height, b.height);
  const px = (img) => { const c = document.createElement("canvas"); c.width = W; c.height = H; const x = c.getContext("2d", { willReadFrequently: true }); x.drawImage(img, 0, 0); return [x.getImageData(0, 0, W, H).data, img.width, img.height]; };
  const [da, aw, ah] = px(a), [db, bw, bh] = px(b);
  const out = wantDiff ? new Uint8ClampedArray(W * H * 4) : null;
  let diff = 0;
  for (let y = 0; y < H; y++) for (let x = 0; x < W; x++) {
    const i = (y * W + x) * 4;
    const inA = x < aw && y < ah, inB = x < bw && y < bh;
    let d = !(inA && inB);
    if (!d) d = Math.max(Math.abs(da[i] - db[i]), Math.abs(da[i + 1] - db[i + 1]), Math.abs(da[i + 2] - db[i + 2])) > tolerance;
    if (d) diff++;
    if (out) { out[i] = d ? 230 : da[i] * 0.3 + 180; out[i + 1] = d ? 40 : da[i + 1] * 0.3 + 180; out[i + 2] = d ? 40 : da[i + 2] * 0.3 + 180; out[i + 3] = 255; }
  }
  let png = null;
  if (out) { const c = document.createElement("canvas"); c.width = W; c.height = H; c.getContext("2d").putImageData(new ImageData(out, W, H), 0, 0); png = c.toDataURL("image/png").split(",")[1]; }
  return { pct: (diff / (W * H)) * 100, size: `${a.width}x${a.height} vs ${b.width}x${b.height}`, png };
}

const browser = await chromium.launch({ executablePath: process.env.PW_CHROME, args: ["--no-sandbox"] });
const rows = [];
try {
  const lc = await browser.newContext();
  const lp = await lc.newPage();
  await lp.goto(`${base}/login`);
  await lp.getByLabel("Benutzername").fill(user);
  await lp.getByLabel("Passwort").fill(password);
  await lp.getByRole("button", { name: "Anmelden" }).click();
  await lp.waitForURL((u) => !u.pathname.startsWith("/login"));
  const ids = Object.fromEntries(await lp.evaluate(async () => (await (await fetch("/api/v1/hosts")).json()).map((h) => [h.name, h.id])));
  const storageState = await lc.storageState();
  await lc.close();
  if (diffDir) mkdirSync(diffDir, { recursive: true });

  for (const scheme of ["light", "dark"]) for (const w of [1440, 390]) {
    const viewport = { width: w, height: w < 768 ? 844 : 900 };
    for (const [name, path] of PAGES) {
      // Login ohne Sitzung, die übrigen Seiten mit Sitzung.
      const ctx = await browser.newContext({ viewport, colorScheme: scheme, reducedMotion: "reduce", ...(name === "login" ? {} : { storageState }) });
      const page = await ctx.newPage();
      await page.goto(base + path.replace(/host:([\w.-]+)/, (_, n) => ids[n]));
      await page.waitForLoadState("networkidle");
      await page.waitForTimeout(500);
      await page.addStyleTag({ content: "nextjs-portal { display: none !important; }" });
      const height = await page.evaluate(() => document.documentElement.scrollHeight);
      const shot = await page.screenshot({ fullPage: true, clip: { x: 0, y: 0, width: w, height: Math.min(height, MAX_H) } });
      const file = `${name}-${w}-${scheme}.png`;
      const ref = readFileSync(join(snapDir, file)).toString("base64");
      const r = await page.evaluate(compare, [ref, shot.toString("base64"), tol, Boolean(diffDir)]);
      if (r.png) writeFileSync(join(diffDir, file), Buffer.from(r.png, "base64"));
      rows.push({ file, ...r });
      console.log(`${r.pct > limit ? "ÜBER " : "ok   "} ${file}: ${r.pct.toFixed(2)} % (${r.size})`);
      await ctx.close();
    }
  }
} finally {
  await browser.close();
}
const over = rows.filter((r) => r.pct > limit);
const lines = ["# Vergleich mit dem Design-Snapshot 2026-11-11", "", `Toleranz je Pixel: ${tol} (größte Kanalabweichung), Schwelle ${limit} %.`, "", "| Bild | abweichende Pixel | Größe (Snapshot vs jetzt) |", "|---|---|---|",
  ...rows.map((r) => `| ${r.file} | ${r.pct.toFixed(2)} %${r.pct > limit ? " (über Schwelle)" : ""} | ${r.size} |`), "", `${over.length} von ${rows.length} über ${limit} %.`];
if (process.argv[2]) writeFileSync(process.argv[2], lines.join("\n") + "\n");
console.log(`${over.length} von ${rows.length} über ${limit} %`);
process.exit(over.length ? 1 : 0);
