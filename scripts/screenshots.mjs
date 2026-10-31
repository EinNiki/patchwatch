// Erzeugt Playwright-Screenshots der Web-UI (hell/dunkel, Desktop/mobil) gegen einen laufenden Stack.
//
//   PW_MODULE=/pfad/zu/node_modules/playwright PW_CHROME=/pfad/zu/chrome \
//   PW_PASSWORD=… node scripts/screenshots.mjs docs/design/v1/screenshots
//
// Umgebung: PW_BASE (Standard http://127.0.0.1:3100), PW_USER (admin), PW_PASSWORD (Pflicht),
// PW_MAX_HEIGHT (Standard 2200), PW_PAGES (Kommaliste "name=/pfad"; "host:<Name>" im Pfad wird zur Host-ID aufgelöst).
import { createRequire } from "node:module";
import { mkdirSync } from "node:fs";

const out = process.argv[2] ?? "screenshots";
const base = (process.env.PW_BASE ?? "http://127.0.0.1:3100").replace(/\/$/, "");
const user = process.env.PW_USER ?? "admin";
const password = process.env.PW_PASSWORD ?? (console.error("PW_PASSWORD setzen"), process.exit(1));
const { chromium } = createRequire(import.meta.url)(process.env.PW_MODULE ?? "playwright");

// Standard: Seiten von UI v2. Für v1 PW_PAGES="hosts=/,host-ubuntu=/hosts/host:web-01,host-proxmox=/hosts/host:pve-01,cves=/cves,settings=/settings".
// Namen mit Eintrag in ACTIONS führen vor dem Foto eine Interaktion aus (Dialog öffnen, Menü aufklappen).
const DEFAULT_PAGES = [
  "hosts=/", "host-ubuntu=/hosts/host:web-01", "host-proxmox=/hosts/host:pve-01",
  "cves=/cves", "cves-filtered=/cves?split=debian_fixed_ubuntu_open", "cve-detail=/cves/CVE-2024-1086",
  "agents=/agents", "agents-waiting=/agents", "agents-add=/agents", "agents-token=/agents",
  "notifications=/notifications", "notification-ntfy=/notifications/ntfy", "notification-matrix=/notifications/matrix",
  "notification-browser=/notifications/browser", "settings=/settings", "menu=/",
].join(",");
const pages = (process.env.PW_PAGES ?? DEFAULT_PAGES).split(",").map((p) => p.split("=", 2));
/** Interaktionen vor dem Foto; `mobileOnly`: nur im schmalen Viewport. */
const ACTIONS = {
  "agents-waiting": async (page) => {
    // Ein früherer Durchlauf kann die Anforderung schon gesetzt haben (Button dann gesperrt).
    const btn = page.getByRole("button", { name: "web-01 jetzt aktualisieren" });
    if (await btn.isEnabled()) await btn.click();
    await page.getByText(/wartet auf Agent|Keine Antwort seit/).first().waitFor();
  },
  "agents-add": async (page) => {
    await page.getByRole("button", { name: "Agent hinzufügen" }).first().click();
    await page.getByLabel("Name des Hosts").fill("web-03");
  },
  // Legt einen Agent an, zeigt den einmaligen Token und löscht den Agent nach dem Foto wieder.
  "agents-token": async (page) => {
    await page.getByRole("button", { name: "Agent hinzufügen" }).first().click();
    await page.getByLabel("Name des Hosts").fill("demo-agent");
    await page.getByRole("button", { name: "Agent anlegen" }).click();
    await page.getByRole("button", { name: "Token kopieren" }).waitFor();
    return async () => {
      await page.getByRole("button", { name: "Fertig, Token gesichert" }).click();
      await page.getByRole("button", { name: "Agent demo-agent löschen" }).click();
      await page.getByRole("button", { name: "demo-agent löschen", exact: true }).click();
      await page.getByRole("row").filter({ hasText: "demo-agent" }).waitFor({ state: "detached" });
    };
  },
  menu: async (page, vp) => {
    if (Number(vp) >= 768) return "skip";
    await page.getByRole("button", { name: "Menü" }).click();
    await page.getByRole("dialog", { name: "Navigation" }).waitFor();
  },
};

// PW_WIDTHS: Kommaliste der Viewport-Breiten; Dateinamen <seite>-<breite>-<schema>.png.
const viewports = Object.fromEntries(
  (process.env.PW_WIDTHS ?? "1440,390").split(",").map((w) => [w.trim(), { width: Number(w), height: Number(w) < 768 ? 844 : 900 }]),
);

mkdirSync(out, { recursive: true });
const browser = await chromium.launch({ executablePath: process.env.PW_CHROME, args: ["--no-sandbox"] });

for (const scheme of ["light", "dark"]) {
  for (const [vpName, viewport] of Object.entries(viewports)) {
    const ctx = await browser.newContext({ viewport, colorScheme: scheme, reducedMotion: "reduce" });
    const page = await ctx.newPage();
    // Lange Listen werden auf PW_MAX_HEIGHT (CSS-px) gekürzt, damit die PNGs im Repo klein bleiben.
    const maxHeight = Number(process.env.PW_MAX_HEIGHT ?? 2200);
    const shot = async (name) => {
      // Das Next.js-Dev-Overlay (Kreis mit "N") gehört nicht ins Bild.
      await page.addStyleTag({ content: "nextjs-portal { display: none !important; }" });
      const height = await page.evaluate(() => document.documentElement.scrollHeight);
      const clip = { x: 0, y: 0, width: viewport.width, height: Math.min(height, maxHeight) };
      await page.screenshot({ path: `${out}/${name}-${vpName}-${scheme}.png`, fullPage: true, clip });
    };

    // Login-Seite vor der Anmeldung (Reihenfolge: erst Screenshot, dann einloggen).
    await page.goto(`${base}/login`);
    await page.getByLabel("Benutzername").waitFor();
    await shot("login");
    await page.getByLabel("Benutzername").fill(user);
    await page.getByLabel("Passwort").fill(password);
    await page.getByRole("button", { name: "Anmelden" }).click();
    await page.waitForURL((u) => !u.pathname.startsWith("/login"));

    const hosts = await page.evaluate(async () => (await (await fetch("/api/v1/hosts")).json()).map((h) => [h.name, h.id]));
    const ids = Object.fromEntries(hosts);
    for (const [name, path] of pages) {
      const resolved = path.replace(/host:([\w.-]+)/, (_, n) => ids[n] ?? (console.error(`Host ${n} fehlt`), process.exit(1)));
      await page.goto(base + resolved);
      await page.waitForLoadState("networkidle");
      await page.waitForTimeout(500); // Daten und Schriften setzen
      const action = ACTIONS[name];
      const cleanup = action ? await action(page, vpName) : undefined;
      if (cleanup === "skip") continue;
      if (action) await page.waitForTimeout(300);
      await shot(name);
      console.log(`${name}-${vpName}-${scheme}`);
      if (typeof cleanup === "function") await cleanup();
    }
    await ctx.close();
  }
}
await browser.close();
