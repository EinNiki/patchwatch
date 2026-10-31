// E2E: Check-in und „Jetzt aktualisieren“ gegen einen laufenden Stack (Server :8080, Web :3100, Docker-Postgres `pw-pg`).
//
// Voraussetzung: Agent `e2e-agent` existiert (UI „Agent hinzufügen“), sein Token liegt in der Datei aus AGENT_CONF (token_file).
//   PW_MODULE=… PW_CHROME=… PW_PWFILE=<Datei mit Admin-Passwort> AGENT=target/debug/patchwatch-agent \
//   CONF=<agent.toml> STATE=<leeres Verzeichnis> node scripts/e2e-checkin.mjs
// Prüft: ohne Anforderung kein Report; Anforderung zeigt „wartet auf Agent …“; der nächste Check-in sendet genau einen Report;
// die UI aktualisiert sich ohne Neuladen; weitere Check-ins senden nichts; zweite Anforderung binnen 60 s wird abgelehnt.
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
const { chromium } = createRequire(import.meta.url)(process.env.PW_MODULE);
const pw = readFileSync(process.env.PW_PWFILE, "utf8").trim();
const { AGENT, CONF, STATE } = process.env;
const sql = (q) => execFileSync("docker", ["exec", "pw-pg", "psql", "-U", "patchwatch", "-d", "patchwatch", "-tAc", q]).toString().trim();
const reports = () => Number(sql("select count(*) from reports r join hosts h on h.id=r.host_id where h.name='e2e-agent'"));
const agent = (...args) => { try { return execFileSync(AGENT, [...args, "--config", CONF], { env: { ...process.env, STATE_DIRECTORY: STATE } }).toString(); } catch (e) { return `exit ${e.status}: ${e.stderr}`; } };
const ok = (c, m) => { console.log(c ? "OK  " : "FAIL", m); if (!c) process.exitCode = 1; };

agent(); // erster Report legt Hostdaten an
const base = reports();
console.log("Reports nach erstem Lauf:", base);

const b = await chromium.launch({ executablePath: process.env.PW_CHROME, args: ["--no-sandbox"] });
const page = await (await b.newContext({ viewport: { width: 1440, height: 900 } })).newPage();
await page.goto("http://127.0.0.1:3100/login");
await page.getByLabel("Benutzername").fill("admin");
await page.getByLabel("Passwort").fill(pw);
await page.getByRole("button", { name: "Anmelden" }).click();
await page.waitForURL((u) => !u.pathname.startsWith("/login"));
await page.goto("http://127.0.0.1:3100/agents");
await page.getByText("Live", { exact: true }).waitFor();
await page.evaluate(() => (window.__noReload = true));
const row = page.getByRole("row").filter({ hasText: "e2e-agent" });
await row.waitFor();
ok(/Agent-Version|0\./.test(await row.textContent()), "Zeile zeigt Agent-Version");

// Check-in ohne Anforderung: nichts passiert.
agent("checkin");
ok(reports() === base, "Check-in ohne Anforderung sendet keinen Report");
await row.getByRole("button", { name: "e2e-agent jetzt aktualisieren" }).click();
await row.getByText("wartet auf Agent").waitFor({ timeout: 5000 });
ok(true, 'UI zeigt „wartet auf Agent …“');
ok(await row.getByRole("button", { name: "e2e-agent jetzt aktualisieren" }).isDisabled(), "Button ist während des Wartens gesperrt");

// Check-in-Intervall zurücksetzen und Agent fragen lassen.
execFileSync("rm", ["-f", `${STATE}/last-checkin`]);
const out = agent("checkin");
console.log(out.trim());
await row.getByText("wartet auf Agent").waitFor({ state: "detached", timeout: 8000 });
ok(true, "Anzeige „wartet“ verschwindet live (ohne Neuladen)");
ok(reports() === base + 1, `genau ein weiterer Report (${reports()} statt ${base + 1})`);
ok(await page.evaluate(() => window.__noReload === true), "Seite wurde nicht neu geladen");
ok(/gerade eben/.test(await row.textContent()), "Letzter Report: gerade eben");

// Zweiter Check-in: keine Anforderung mehr → kein Report.
execFileSync("rm", ["-f", `${STATE}/last-checkin`]);
agent("checkin");
ok(reports() === base + 1, "weiterer Check-in sendet nichts");

// Rate-Limit: sofort erneut anfordern → 429 → Hinweis.
await row.getByRole("button", { name: "e2e-agent jetzt aktualisieren" }).click();
await page.getByText(/Erneut möglich in \d+ Sek/).waitFor({ timeout: 5000 });
ok(true, "Zweite Anforderung innerhalb von 60 s wird abgelehnt und erklärt");
await b.close();
