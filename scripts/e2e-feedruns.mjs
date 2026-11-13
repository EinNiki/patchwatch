// E2E: Abruf-Läufe der CVE-Quellen (Stepper, Anhängen bei 409, Bestätigung bei 428, Warnung bei 429, Fehlschlag mit Wiederholen,
// Einklappen nach 5 s). Die Läufe-Endpunkte werden per page.route nachgestellt; der Server bekommt keine Schreibzugriffe.
//   PW_MODULE=… PW_CHROME=… PW_PWFILE=<Datei mit Admin-Passwort> [PW_SHOTS=<Ordner>] node scripts/e2e-feedruns.mjs
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
const { chromium } = createRequire(import.meta.url)(process.env.PW_MODULE);
const pw = readFileSync(process.env.PW_PWFILE, "utf8").trim();
const base = process.env.PW_BASE ?? "http://127.0.0.1:3100";
const shots = process.env.PW_SHOTS;
const ok = (c, m) => { console.log(c ? "OK  " : "FAIL", m); if (!c) process.exitCode = 1; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const json = (status, body, headers = {}) => ({ status, contentType: "application/json", headers, body: JSON.stringify(body) });

const mkRun = (o) => ({ id: 1, source: "", trigger: "manual", started_by: "admin", status: "running", phase: "connect", created_at: new Date().toISOString(), started_at: new Date().toISOString(), finished_at: null, bytes: 0, items: null, hosts: null, error: null, phases: {}, ...o });

async function open(browser, viewport, scheme = "light") {
  const ctx = await browser.newContext({ viewport, colorScheme: scheme });
  const page = await ctx.newPage();
  await page.goto(`${base}/login`);
  await page.getByLabel("Benutzername").fill("admin");
  await page.getByLabel("Passwort").fill(pw);
  await page.getByRole("button", { name: "Anmelden" }).click();
  await page.waitForURL((u) => !u.pathname.startsWith("/login"));
  return page;
}

const browser = await chromium.launch({ executablePath: process.env.PW_CHROME, args: ["--no-sandbox"] });
try {
  const page = await open(browser, { width: 1440, height: 900 });
  // Zustand der nachgestellten Läufe; jede Abfrage der Liste schaltet einen Lauf eine Phase weiter.
  const st = { runs: [], posts: [], mode: "ok" };
  const phases = ["connect", "download", "parse", "store", "evaluate"];
  await page.route("**/api/v1/feeds/runs**", (r) => {
    for (const run of st.runs) {
      if (run.status === "queued") { run.status = "running"; continue; }
      if (run.status !== "running") continue;
      const i = phases.indexOf(run.phase);
      run.bytes += 400_000;
      if (st.mode === "fail" && run.phase === "download") {
        Object.assign(run, { status: "failed", error: "Quelle antwortet nicht (Zeitüberschreitung).", finished_at: new Date().toISOString() });
      } else if (i === phases.length - 1) {
        Object.assign(run, { status: "ok", phase: "done", items: 1234, hosts: 7, finished_at: new Date().toISOString(), phases: { connect: 300, download: 1200, parse: 800, store: 400, evaluate: 600 } });
      } else run.phase = phases[i + 1];
    }
    return r.fulfill(json(200, { runs: st.runs }));
  });
  await page.goto(`${base}/cves`);
  const row = page.getByRole("row").filter({ hasText: /Debian/ }).first();
  await row.waitFor();
  const start = page.getByRole("button", { name: /^Debian jetzt abrufen$/ });
  const region = page.getByRole("region", { name: "Benachrichtigungen" });
  // Quelle ermitteln (ID aus der echten Liste).
  const feeds = await page.evaluate(() => fetch("/api/v1/feeds").then((r) => r.json()));
  const deb = feeds.find((f) => f.label === "Debian") ?? feeds[0];
  ok(!!deb, `Quelle gefunden (${deb?.source})`);

  // 1) Normaler Lauf: 202, Stepper, Phasen, Erfolg, Zusammenfassung, Einklappen nach 5 s.
  await page.route(`**/api/v1/feeds/${deb.source}/run`, (r) => {
    st.posts.push(r.request().postDataJSON());
    st.runs = [mkRun({ id: 11, source: deb.source, status: "queued" })];
    return r.fulfill(json(202, { run: st.runs[0] }));
  });
  await start.click();
  const stepper = page.getByRole("group", { name: /^Abruf Debian$/ });
  await stepper.waitFor();
  ok((await stepper.getByRole("listitem").count()) === 6, "Stepper hat sechs Schritte");
  ok((await stepper.locator('[aria-current="step"]').count()) <= 1, "höchstens ein aktueller Schritt (aria-current)");
  ok((await page.getByRole("button", { name: "Debian: Abruf läuft" }).getAttribute("aria-busy")) === "true", "Knopf ist während des Laufs beschäftigt (aria-busy, nicht bedienbar; Name „Debian: Abruf läuft“)");
  if (shots) await page.screenshot({ path: `${shots}/run-1440-active.png` });
  await page.waitForFunction(() => document.body.innerText.includes("Hosts prüfen"), null, { timeout: 20000 });
  await region.getByText(/Debian: aktualisiert/).waitFor({ timeout: 20000 });
  ok(/1234 Einträge · 7 Hosts/.test(await region.innerText()), "Zusammenfassung mit Zählern als Toast");
  ok((await stepper.count()) === 1, "Stepper bleibt nach dem Erfolg zunächst sichtbar");
  if (shots) await page.screenshot({ path: `${shots}/run-1440-done.png` });
  await stepper.waitFor({ state: "detached", timeout: 8000 });
  ok(true, "Stepper klappt nach ~5 s ein");
  ok(st.posts.length === 1 && st.posts[0] === undefined || st.posts[0] && Object.keys(st.posts[0]).length === 0, "Start ohne Bestätigung gesendet");

  // 2) 409: an den laufenden Lauf anhängen, kein roter Fehler.
  await page.unroute(`**/api/v1/feeds/${deb.source}/run`);
  st.runs = [mkRun({ id: 22, source: deb.source, status: "running", phase: "download", bytes: 900_000 })];
  await page.route(`**/api/v1/feeds/${deb.source}/run`, (r) => r.fulfill(json(409, { error: "Ein Abruf läuft bereits.", code: "running", run_id: 22 })));
  await page.getByRole("button", { name: /^Debian jetzt abrufen$/ }).click({ force: true }).catch(() => {});
  await stepper.waitFor();
  ok((await region.getByRole("alert").count()) === 0, "409 zeigt keinen Fehler-Toast");
  ok(/läuft bereits/.test(await region.innerText()), "409 meldet freundlich, dass ein Abruf läuft");
  st.runs = [];

  // 3) 428: Rückfrage, Bestätigung sendet confirm:true.
  await page.unroute(`**/api/v1/feeds/${deb.source}/run`);
  let confirmBody = null;
  await page.route(`**/api/v1/feeds/${deb.source}/run`, (r) => {
    const b = r.request().postDataJSON();
    if (b?.confirm) { confirmBody = b; st.runs = [mkRun({ id: 33, source: deb.source, status: "queued" })]; return r.fulfill(json(202, { run: st.runs[0] })); }
    return r.fulfill(json(428, { error: "Quelle im Wartezustand.", code: "backoff", failures: 3, next_attempt_at: new Date(Date.now() + 600_000).toISOString() }));
  });
  await page.getByRole("button", { name: /^Debian jetzt abrufen$/ }).click();
  const dlg = page.getByRole("dialog");
  await dlg.waitFor();
  ok(/3 Fehlversuchen/.test(await dlg.innerText()), "Rückfrage nennt die Fehlversuche");
  if (shots) await page.screenshot({ path: `${shots}/run-1440-confirm.png` });
  await dlg.getByRole("button", { name: "Trotzdem abrufen" }).click();
  await stepper.waitFor();
  ok(confirmBody?.confirm === true, "Bestätigung sendet confirm:true");
  await stepper.waitFor({ state: "detached", timeout: 30000 });

  // 4) 429: Warnung mit Wartezeit.
  await page.unroute(`**/api/v1/feeds/${deb.source}/run`);
  await page.route(`**/api/v1/feeds/${deb.source}/run`, (r) => r.fulfill(json(429, { error: "Zu viele Abrufe.", code: "too_soon", retry_after: 42 }, { "retry-after": "42" })));
  await page.getByRole("button", { name: /^Debian jetzt abrufen$/ }).click();
  await region.getByText(/42 s/).waitFor();
  ok((await region.getByRole("alert").count()) === 0, "429 ist eine Warnung, kein Fehler");

  // 5) Fehlschlag: Stepper bleibt, Fehlermeldung, Wiederholen startet neu.
  await page.unroute(`**/api/v1/feeds/${deb.source}/run`);
  st.mode = "fail";
  let posts = 0;
  await page.route(`**/api/v1/feeds/${deb.source}/run`, (r) => { posts++; st.runs = [mkRun({ id: 40 + posts, source: deb.source, status: "queued" })]; return r.fulfill(json(202, { run: st.runs[0] })); });
  await page.getByRole("button", { name: /^Debian jetzt abrufen$/ }).click();
  await stepper.getByText("Quelle antwortet nicht").waitFor({ timeout: 20000 });
  ok(/Fehlgeschlagen bei „Herunterladen“/.test(await stepper.innerText()), "Fehlschlag nennt den Schritt");
  await sleep(6000);
  ok((await stepper.count()) === 1, "Stepper bleibt bei Fehlern stehen (kein Einklappen)");
  if (shots) await page.screenshot({ path: `${shots}/run-1440-failed.png` });
  st.mode = "ok";
  await stepper.getByRole("button", { name: "Erneut versuchen" }).click();
  await page.waitForFunction(() => document.querySelector('[aria-label="Abruf Debian"]')?.textContent?.includes("Verbinden"));
  ok(posts === 2, "„Erneut versuchen“ startet einen neuen Lauf");
  await page.context().close();

  // 6) Layout in vier Breiten, hell und dunkel: kein horizontales Scrollen der Seite.
  for (const scheme of ["light", "dark"]) for (const w of [390, 768, 1440, 1920]) {
    const p = await open(browser, { width: w, height: 900 }, scheme);
    await p.route("**/api/v1/feeds/runs**", (r) => r.fulfill(json(200, { runs: [mkRun({ id: 77, source: deb.source, status: "running", phase: "parse", bytes: 2_400_000, phases: { connect: 300, download: 1500 } })] })));
    await p.goto(`${base}/cves`);
    await p.getByRole("group", { name: /^Abruf / }).waitFor();
    const over = await p.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    ok(over <= 0, `${scheme} ${w}px: kein horizontales Scrollen der Seite (${over})`);
    if (shots) await p.screenshot({ path: `${shots}/run-${w}-${scheme}.png` });
    await p.context().close();
  }
} finally {
  await browser.close();
}
