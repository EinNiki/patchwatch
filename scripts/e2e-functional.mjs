// E2E (funktional): Anmeldung, Hosts und Agent-Token, Check-in, Watchlist, Filter/Sortierung/Suche, Quellenverwaltung,
// Abruf-Läufe, Benachrichtigungskanäle, Live-Updates, Profilbild. API-Ebene mit fetch, Browser nur dort, wo die UI zählt.
// Verändert Daten: nur gegen den Wegwerf-Stack (scripts/dev-stack.sh), danach `down && up` für den Seed-Zustand.
//
//   scripts/dev-stack.sh restart-server        # davor immer (Login-Limit); siehe unten für die Server-Umgebung
//   PW_MODULE=… PW_CHROME=… PW_PWFILE=<Admin-Passwort-Datei> [PW_BASE=http://127.0.0.1:3300] [PW_API=http://127.0.0.1:8091]
//   [PW_MOCK=http://127.0.0.1:8190] [PW_PG_NAME=pw-night-pg] [PW_AGENT=<patchwatch-agent>] node scripts/e2e-functional.mjs
//
// Server-Umgebung für den vollen Umfang (vor `restart-server` exportieren, es erbt sie):
//   PATCHWATCH_SECRET_KEY=$(openssl rand -base64 32)       Geheimnisse der Benachrichtigungskanäle speichern
//   PATCHWATCH_CONFIG=<toml> mit  [cve] request_timeout_secs = 2, retries = 2, retry_base_delay_ms = 200
//                                                              Zeitüberschreitung und Wiederholungen in Sekunden prüfen
// Fehlt eines davon, wird der betroffene Teil als SKIP gemeldet (nicht als bestanden). Die Mock-Feeds bekommen den Fehlermodus
// über POST /__mode (scripts/mock-feeds.mjs); der Mindestabstand der Abrufe wird über die Datenbank des Stacks verkürzt
// (UPDATE feed_runs …, nur Wegwerf-Datenbank). Es gehen keine Anfragen an echte Feed-Quellen.
// Das Admin-Passwort wird geändert und am Ende zurückgesetzt (auch bei Fehlern); Tokens und Geheimnisse werden nie ausgegeben.
// Exit 1 bei jedem FAIL.
import { createRequire } from "node:module";
import { readFileSync, mkdtempSync, writeFileSync, rmSync, statSync } from "node:fs";
import { execFileSync, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { request as httpRequest } from "node:http";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

const { chromium } = createRequire(import.meta.url)(process.env.PW_MODULE);
const PW = readFileSync(process.env.PW_PWFILE, "utf8").trim();
const WEB = process.env.PW_BASE ?? "http://127.0.0.1:3300";
const API = process.env.PW_API ?? "http://127.0.0.1:8091";
const MOCK = process.env.PW_MOCK ?? "http://127.0.0.1:8190";
const PG = process.env.PW_PG_NAME ?? "pw-night-pg";
const AGENT = process.env.PW_AGENT ?? new URL("../target/debug/patchwatch-agent", import.meta.url).pathname;
const USER = process.env.PW_USER ?? "admin";

let fails = 0;
const ok = (c, m) => { console.log(c ? "OK  " : "FAIL", m); if (!c) { fails++; process.exitCode = 1; } };
const skip = (m) => console.log("SKIP", m);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sql = (q) => execFileSync("docker", ["exec", PG, "psql", "-U", "patchwatch", "-d", "patchwatch", "-tAc", q]).toString().trim();
async function until(fn, ms = 20000, step = 400) {
  const end = Date.now() + ms;
  for (;;) { const v = await fn(); if (v) return v; if (Date.now() > end) return null; await sleep(step); }
}

// ---- HTTP-Hilfen -----------------------------------------------------------------------------------------------------
class Session {
  constructor() { this.cookie = ""; this.csrf = ""; }
  async call(method, path, { body, raw, headers = {}, csrf = true, token, noCookie = false } = {}) {
    const h = { ...headers };
    if (this.cookie && !noCookie) h.cookie = this.cookie;
    if (csrf && this.csrf && method !== "GET") h["x-csrf-token"] = this.csrf;
    if (token) h.authorization = `Bearer ${token}`;
    let data;
    if (raw !== undefined) data = raw;
    else if (body !== undefined) { h["content-type"] = "application/json"; data = JSON.stringify(body); }
    let r;
    for (let i = 0; ; i++) {
      try { r = await fetch(API + path, { method, headers: h, body: data, redirect: "manual" }); break; }
      catch (e) { if (i >= 2) throw e; await sleep(300); } // veraltete Keep-Alive-Verbindung nach Server-Neustart
    }
    const text = await r.text();
    let json; try { json = text ? JSON.parse(text) : null; } catch { json = null; }
    return { status: r.status, json, text, headers: r.headers };
  }
  async login(user, password) {
    loginAttempts++;
    const r = await this.call("POST", "/api/v1/auth/login", { body: { username: user, password }, csrf: false });
    if (r.status === 200) {
      const sc = r.headers.getSetCookie().map((c) => c.split(";")[0]);
      this.cookie = sc.join("; "); this.csrf = r.json.csrf_token;
    }
    return r;
  }
}
let loginAttempts = 0;
const admin = new Session();
const leaks = (text, secret) => text.includes(secret);

function report(host, over = {}) {
  return {
    schema_version: 1, agent_version: "0.1.0", hostname: host, collected_at_unix: 1,
    os: { id: "ubuntu", version_id: "24.04", codename: "noble", pretty_name: "Ubuntu 24.04.3 LTS" },
    kernel: {
      running_release: "6.8.0-79-generic",
      running_package: { name: "linux-image-6.8.0-79-generic", version: "6.8.0-79.79", source: "linux-signed", source_version: "6.8.0-79.79" },
      newest_installed_release: "6.8.0-79-generic",
      newest_installed_package: { name: "linux-image-6.8.0-79-generic", version: "6.8.0-79.79", source: "linux-signed", source_version: "6.8.0-79.79" },
      reboot_needed_kernel: false,
    },
    reboot_required_file: false, updates: { pending: 0, security: 0 }, uptime_seconds: 1000, proxmox: null, packages: null, ...over,
  };
}

let browser; let page;
async function ui() {
  if (page) return page;
  loginAttempts++;
  browser = await chromium.launch({ executablePath: process.env.PW_CHROME, args: ["--no-sandbox"] });
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  await ctx.addInitScript(() => { try { localStorage.setItem("pw-feeds-manage", "1"); } catch { /* ohne Speicher */ } });
  page = await ctx.newPage();
  await page.goto(`${WEB}/login`);
  await page.getByLabel("Benutzername").fill(USER);
  await page.getByLabel("Passwort").fill(PW);
  await page.getByRole("button", { name: "Anmelden" }).click();
  await page.waitForURL((u) => !u.pathname.startsWith("/login"));
  return page;
}

async function section(name, fn) {
  console.log(`\n== ${name}`);
  try { await fn(); } catch (e) { ok(false, `${name}: unerwartete Ausnahme: ${String(e?.stack ?? e).split("\n").slice(0, 3).join(" | ")}`); }
}

const NEWPW = `Func-${randomBytes(9).toString("hex")}-Pw!`;

// ---- 1. Anmeldung und Passwort ---------------------------------------------------------------------------------------
await section("Anmeldung und Passwortwechsel", async () => {
  const anon = new Session();
  ok((await anon.call("GET", "/api/v1/auth/me")).status === 401, "ohne Session: /auth/me 401");
  ok((await anon.call("GET", "/api/v1/hosts")).status === 401, "ohne Session: /hosts 401");
  const bad = await anon.login(USER, "falsches-Passwort-123");
  ok(bad.status === 401, `falsches Passwort: 401 (${bad.status})`);
  const unk = await anon.login("gibt-es-nicht", "falsches-Passwort-123");
  ok(unk.status === 401 && unk.text === bad.text, "unbekannter Benutzer: gleiche Antwort wie falsches Passwort (kein Hinweis auf Konten)");
  const good = await admin.login(USER, PW);
  ok(good.status === 200 && !!admin.csrf, "Anmeldung mit Passwort aus der Datei");
  ok(/HttpOnly/i.test(good.headers.getSetCookie().join(";")) && /SameSite=Strict/i.test(good.headers.getSetCookie().join(";")), "Session-Cookie HttpOnly und SameSite=Strict");
  ok(!leaks(good.text, PW), "Antwort enthält das Passwort nicht");
  ok((await admin.call("GET", "/api/v1/auth/me")).status === 200, "/auth/me mit Session 200");
  ok((await admin.call("POST", "/api/v1/hosts", { body: { name: "csrf-test" }, csrf: false })).status === 403, "verändernder Aufruf ohne CSRF-Token: 403");

  // Passwortwechsel: Fehlerfälle, Erfolg, altes Passwort ungültig, Rückgabe des ursprünglichen Passworts.
  let changed = false;
  try {
    const cp = (cur, neu) => admin.call("POST", "/api/v1/auth/password", { body: { current_password: cur, new_password: neu } });
    ok((await cp("falsch-falsch-falsch", NEWPW)).status === 403, "Passwortwechsel mit falschem aktuellem Passwort: 403 (Passwort bleibt)");
    ok((await cp(PW, "kurz")).status === 400, "zu kurzes neues Passwort: 400");
    ok((await cp(PW, PW)).status === 400, "neues Passwort gleich dem alten: 400");
    const r = await cp(PW, NEWPW);
    ok(r.status === 204 || r.status === 200, `Passwortwechsel (${r.status})`);
    changed = r.status < 300;
    if (changed) {
      const s2 = new Session();
      ok((await s2.login(USER, PW)).status === 401, "altes Passwort wird abgelehnt");
      ok((await s2.login(USER, NEWPW)).status === 200, "neues Passwort funktioniert");
      const back = await s2.call("POST", "/api/v1/auth/password", { body: { current_password: NEWPW, new_password: PW } });
      ok(back.status < 300, `Passwort zurück auf das Passwort aus der Datei (${back.status})`);
      changed = back.status >= 300;
    }
  } finally {
    if (changed) { // Notausgang: Passwort sicher zurücksetzen
      const s3 = new Session();
      if ((await s3.login(USER, NEWPW)).status === 200) await s3.call("POST", "/api/v1/auth/password", { body: { current_password: NEWPW, new_password: PW } });
    }
  }
  const again = await admin.login(USER, PW);
  ok(again.status === 200, "danach Anmeldung mit dem Passwort aus der Datei");
});

// ---- 2. Hosts, Token, Report, Check-in ------------------------------------------------------------------------------
await section("Hosts, Agent-Token, Report und Check-in", async () => {
  const name = `func-${randomBytes(3).toString("hex")}`;
  const c = await admin.call("POST", "/api/v1/hosts", { body: { name } });
  ok(c.status === 201 && /^pw_[A-Za-z0-9_-]{16,128}$/.test(c.json?.token ?? ""), "Host anlegen: 201 und Token im Format pw_…");
  const id = c.json.id; let token = c.json.token;
  ok((await admin.call("POST", "/api/v1/hosts", { body: { name } })).status === 409, "doppelter Hostname: 409");
  for (const bad of ["", "a b", "x".repeat(64), "<script>", "../etc"]) {
    ok((await admin.call("POST", "/api/v1/hosts", { body: { name: bad } })).status === 400, `ungültiger Hostname ${JSON.stringify(bad.slice(0, 12))}: 400`);
  }
  const list = await admin.call("GET", "/api/v1/hosts");
  const detail = await admin.call("GET", `/api/v1/hosts/${id}`);
  ok(!leaks(list.text, token) && !leaks(detail.text, token) && !/token_hash/.test(list.text + detail.text), "Token nur einmal sichtbar: weder in Liste noch Detail, kein Hash");

  const rep = (t, body = report(name)) => admin.call("POST", "/api/v1/report", { body, token: t, noCookie: true });
  ok((await admin.call("POST", "/api/v1/report", { body: report(name), noCookie: true })).status === 401, "Report ohne Token: 401");
  ok((await rep("pw_" + "x".repeat(40))).status === 401, "Report mit ungültigem Token: 401");
  ok((await admin.call("POST", "/api/v1/report", { raw: "{kaputt", headers: { "content-type": "application/json" }, token, noCookie: true })).status === 400, "kaputtes JSON mit gültigem Token: 400");
  const r1 = await rep(token);
  ok(r1.status >= 200 && r1.status < 300, `Report mit dem neuen Token (${r1.status})`);
  const h1 = (await admin.call("GET", "/api/v1/hosts")).json.find((h) => h.id === id);
  ok(!!h1 && h1.status !== "pending", `Host zeigt nach dem Report Daten (Status ${h1?.status})`);

  const checkin = async (t, q = "") => (await admin.call("POST", `/api/v1/agent/checkin${q}`, { token: t, noCookie: true }));
  const ci0 = await checkin(token);
  ok(ci0.status === 200 && ci0.json?.report_requested === false && Object.keys(ci0.json).length === 1, 'Check-in ohne Anforderung: genau {"report_requested": false}');
  ok((await checkin("pw_" + "y".repeat(40))).status === 401, "Check-in mit ungültigem Token: 401");
  const rq = await admin.call("POST", `/api/v1/hosts/${id}/request-report`);
  ok(rq.status === 200 && rq.json?.requested === 1, "„Daten jetzt abrufen“: 200");
  const a = await checkin(token), b = await checkin(token);
  ok(a.json?.report_requested === true && b.json?.report_requested === false, "genau ein report_requested=true je Anforderung");
  const rq2 = await admin.call("POST", `/api/v1/hosts/${id}/request-report`);
  ok(rq2.status === 429 && Number(rq2.headers.get("retry-after")) >= 1, "zweite Anforderung binnen 60 s: 429 mit Retry-After");
  sql(`UPDATE hosts SET last_report_request_at = now() - interval '5 minutes' WHERE id = ${id}`);
  // Long-Poll: Anfrage wartet und bekommt „true“ sofort, sobald die Anforderung eintrifft.
  const t0 = Date.now();
  const waiting = checkin(token, "?wait=10");
  await sleep(700);
  ok((await admin.call("POST", `/api/v1/hosts/${id}/request-report`)).status === 200, "Anforderung während Long-Poll");
  const lp = await waiting;
  ok(lp.json?.report_requested === true && Date.now() - t0 < 6000, `Long-Poll liefert „true“ binnen Sekunden (${Date.now() - t0} ms)`);
  ok((await checkin(token)).json?.report_requested === false, "danach wieder nur „false“");
  ok((await rep(token)).status < 300, "Report auf Anforderung");
  const all = await admin.call("POST", "/api/v1/hosts/request-report");
  ok(all.status === 200 && Number.isInteger(all.json?.requested), `„Alle Daten abrufen“: 200 (${JSON.stringify(all.json)})`);
  sql("UPDATE hosts SET report_requested_at = NULL, report_dispatched_at = NULL");

  // Token erneuern, Host löschen.
  const rot = await admin.call("POST", `/api/v1/hosts/${id}/rotate-token`);
  const old = token; token = rot.json?.token;
  ok(rot.status === 200 && /^pw_/.test(token ?? "") && token !== old, "Token erneuern: neuer Token");
  ok((await rep(old)).status === 401 && (await checkin(old)).status === 401, "alter Token: Report und Check-in 401");
  ok((await rep(token)).status < 300 && (await checkin(token)).status === 200, "neuer Token funktioniert");
  ok((await admin.call("POST", "/api/v1/hosts/99999999/rotate-token")).status === 404, "Token erneuern bei unbekanntem Host: 404");
  const del = await admin.call("DELETE", `/api/v1/hosts/${id}`);
  ok(del.status === 204 || del.status === 200, `Host löschen (${del.status})`);
  ok((await admin.call("GET", `/api/v1/hosts/${id}`)).status === 404, "gelöschter Host: 404");
  ok((await rep(token)).status === 401 && (await checkin(token)).status === 401, "Token des gelöschten Hosts: 401");
  ok((await admin.call("DELETE", `/api/v1/hosts/${id}`)).status === 404, "erneut löschen: 404");
});

await section("Agent-Binary gegen den Stack (temporäres Verzeichnis, ohne Root)", async () => {
  try { statSync(AGENT); } catch { skip(`Agent-Binary fehlt (${AGENT}); siehe agent/tests/cli.rs`); return; }
  const name = `func-ag-${randomBytes(3).toString("hex")}`;
  const c = await admin.call("POST", "/api/v1/hosts", { body: { name } });
  const token = c.json.token; const dir = mkdtempSync(join(tmpdir(), "pw-func-agent-"));
  const conf = join(dir, "agent.toml"); const tokfile = join(dir, "token");
  writeFileSync(conf, `server_url = "${API}"\ninsecure_http = true\ntimeout_secs = 20\ntoken_file = "${tokfile}"\n`);
  const run = (args, input) => spawnSync(AGENT, [...args, "--config", conf], { input, env: { PATH: process.env.PATH, STATE_DIRECTORY: dir }, encoding: "utf8", timeout: 60000 });
  const clean = (r) => !`${r.stdout}${r.stderr}`.includes(token);
  try {
    const st = run(["set-token", "--stdin"], token + "\n");
    const wrote = (() => { try { return (statSync(tokfile).mode & 0o777) === 0o600; } catch { return false; } })();
    ok(st.status === 0 && wrote, `set-token --stdin schreibt die Token-Datei mit 0600 (Exit ${st.status})`);
    ok(clean(st), "set-token gibt den Token nicht aus");
    if (st.status !== 0) { console.log(`INFO set-token: ${(st.stderr || st.stdout).slice(0, 200).replace(token, "***")}`); return; }
    const rp = run([], undefined);
    ok(rp.status === 0 && clean(rp), `Agent-Lauf gegen den Server: Exit 0 (${rp.status}), Token nicht ausgegeben`);
    const h = (await admin.call("GET", "/api/v1/hosts")).json.find((x) => x.name === name);
    ok(!!h && h.status !== "pending", `Server hat den Report des echten Agents (Status ${h?.status})`);
    const ci = run(["checkin"], undefined);
    ok(ci.status === 0 && clean(ci), `Agent checkin ohne Anforderung: Exit 0, sendet nichts (${ci.status})`);
    const ss = run(["status"], undefined);
    ok(clean(ss), "Agent status gibt den Token nicht aus");
    writeFileSync(tokfile, "pw_" + "z".repeat(40) + "\n");
    const bad = run([], undefined);
    ok(bad.status === 4, `falscher Token: Exit 4 (${bad.status})`);
  } finally { rmSync(dir, { recursive: true, force: true }); await admin.call("DELETE", `/api/v1/hosts/${c.json.id}`); }
});

// ---- 3. Watchlist, Filter, Sortierung, Suche ------------------------------------------------------------------------
await section("CVE-Liste: Watchlist, Filter, Sortierung, Paginierung, Suche", async () => {
  const all = (await admin.call("GET", "/api/v1/cves?affects=all&limit=500")).json;
  ok(Array.isArray(all) && all.length > 5, `Demo-CVEs vorhanden (${all?.length})`);
  const mine = (await admin.call("GET", "/api/v1/cves?affects=mine&limit=500")).json;
  const ids = new Set(all.map((c) => c.id));
  ok(mine.every((c) => ids.has(c.id)) && mine.length <= all.length, `„Betrifft“ mine (${mine.length}) ist Teilmenge von all (${all.length})`);
  const [x, y] = [all[0].id, all[1].id];
  await admin.call("DELETE", `/api/v1/watchlist/${x}`); await admin.call("DELETE", `/api/v1/watchlist/${y}`);
  ok((await admin.call("PUT", `/api/v1/watchlist/${x}`)).status === 204, "Stern setzen: 204");
  ok((await admin.call("PUT", `/api/v1/watchlist/${x}`)).status === 204, "Stern erneut setzen (idempotent): 204");
  ok((await admin.call("PUT", "/api/v1/watchlist/kein-cve")).status === 400, "ungültige CVE-ID: 400");
  ok((await admin.call("PUT", `/api/v1/watchlist/${y}`, { body: { note: "n".repeat(501) } })).status === 400, "Notiz > 500 Zeichen: 400");
  const wl = (await admin.call("GET", "/api/v1/cves?watchlist=true&affects=all")).json;
  ok(wl.length === 1 && wl[0].id === x && wl[0].watched === true, "„nur Watchlist“ zeigt genau den markierten Eintrag");
  ok((await admin.call("GET", "/api/v1/watchlist")).json.some((c) => c.id === x), "/watchlist enthält ihn");
  ok((await admin.call("DELETE", `/api/v1/watchlist/${x}`)).status === 204, "Entfernen: 204");
  ok((await admin.call("PUT", `/api/v1/watchlist/${x}`)).status === 204 && (await admin.call("GET", `/api/v1/cves?watchlist=true&affects=all`)).json.some((c) => c.id === x), "Rückgängig (erneut setzen) bringt den Eintrag zurück");
  await admin.call("DELETE", `/api/v1/watchlist/${x}`);

  for (const q of ["distro=debian", "distro=ubuntu", "debian=open", "debian=fixed", "ubuntu=open", "ubuntu=fixed", "debian=open&ubuntu=open", "distro=debian&ubuntu=fixed&affects=all", "releases=all", "split=debian_fixed_ubuntu_open"]) {
    const r = await admin.call("GET", `/api/v1/cves?${q}&limit=500`);
    ok(r.status === 200 && Array.isArray(r.json), `Filter ${q}: 200 (${r.json?.length} Treffer)`);
  }
  const deb = (await admin.call("GET", "/api/v1/cves?distro=debian&affects=all&limit=500")).json;
  const ubu = (await admin.call("GET", "/api/v1/cves?distro=ubuntu&affects=all&limit=500")).json;
  ok(deb.length <= all.length && ubu.length <= all.length && deb.length + ubu.length >= all.length, `Debian (${deb.length}) und Ubuntu (${ubu.length}) decken alle (${all.length}) ab`);
  for (const sort of ["hosts", "latest", "level", "updated"]) for (const dir of ["asc", "desc"]) {
    const r = await admin.call("GET", `/api/v1/cves?affects=all&sort=${sort}&dir=${dir}&limit=500`);
    ok(r.status === 200 && r.json.length === all.length, `Sortierung ${sort} ${dir}: 200, gleiche Menge`);
    if (sort === "latest") {
      const t = r.json.map((c) => c.published_at ? Date.parse(c.published_at) : null).filter((v) => v !== null);
      const sorted = [...t].sort((p, q) => (dir === "asc" ? p - q : q - p));
      ok(JSON.stringify(t) === JSON.stringify(sorted), `latest ${dir}: Veröffentlichungsdatum monoton`);
    }
    if (sort === "level") {
      const t = r.json.map((c) => c.level);
      const sorted = [...t].sort((p, q) => (dir === "asc" ? p - q : q - p));
      ok(JSON.stringify(t) === JSON.stringify(sorted), `level ${dir}: Stufe monoton`);
    }
  }
  ok((await admin.call("GET", "/api/v1/cves?sort=quatsch")).status === 400, "unbekannte Sortierung: 400");
  // Paginierung
  const p1 = (await admin.call("GET", "/api/v1/cves?affects=all&limit=4&offset=0&sort=latest")).json;
  const p2 = (await admin.call("GET", "/api/v1/cves?affects=all&limit=4&offset=4&sort=latest")).json;
  const p8 = (await admin.call("GET", "/api/v1/cves?affects=all&limit=8&offset=0&sort=latest")).json;
  ok(JSON.stringify([...p1, ...p2].map((c) => c.id)) === JSON.stringify(p8.map((c) => c.id)) && p1.length === 4, "Seiten (limit/offset) ergeben zusammen die erste große Seite, ohne Doppelte");
  for (const q of ["limit=0", "limit=-5", "limit=999999", "offset=-3", "offset=99999999"]) {
    ok((await admin.call("GET", `/api/v1/cves?affects=all&${q}`)).status < 500, `Grenzwert ${q}: kein 5xx`);
  }
  // Suche: nie 5xx, harmlose Treffer.
  const terms = ["café", "日本語", "😀🔥", "'", '"', ";", "--", "%", "_", "'; DROP TABLE cves; --", "' OR '1'='1", "\\", "a%b_c", "x".repeat(300), "CVE-2024", "\u0000", "<script>alert(1)</script>", "%00", " "];
  let bad = [];
  for (const t of terms) {
    const r = await admin.call("GET", `/api/v1/cves?affects=all&q=${encodeURIComponent(t)}`);
    if (r.status >= 500 || !(r.status === 200 || r.status === 400)) bad.push(`${JSON.stringify(t.slice(0, 20))}→${r.status}`);
  }
  ok(bad.length === 0, `Suche mit Sonderzeichen/Emoji/SQL-Metazeichen/300 Zeichen: nie 5xx${bad.length ? " (" + bad.join(", ") + ")" : ""}`);
  ok((await admin.call("GET", "/api/v1/cves?affects=all&q=%25")).json.length < all.length, "Suche „%“ wirkt nicht als Platzhalter (weniger als alle)");
  ok((await admin.call("GET", "/api/v1/cves?affects=all&q=" + encodeURIComponent("'; DROP TABLE cves; --"))).json?.length === 0
    && (await admin.call("GET", "/api/v1/cves?affects=all&limit=1")).json.length === 1, "SQL-Einschleusung ohne Wirkung (Tabelle besteht)");
  const sample = all[0].id;
  ok((await admin.call("GET", `/api/v1/cves?affects=all&q=${sample}`)).json.some((c) => c.id === sample), "Suche nach vollständiger CVE-ID findet sie");
  for (const bid of ["x", "CVE-1", "%27", "..%2F..", "CVE-2024-0001%00"]) ok((await admin.call("GET", `/api/v1/cves/${bid}`)).status < 500, `CVE-Detail mit ${bid}: kein 5xx`);

  // Oberfläche: „Weitere laden“ (Seitengröße 100).
  if (all.length > 100) {
    const p = await ui(); await p.goto(`${WEB}/cves?affects=all`);
    const rows = () => p.locator("table tbody tr").count();
    await p.getByRole("button", { name: "Weitere laden" }).waitFor();
    const n0 = await rows(); await p.getByRole("button", { name: "Weitere laden" }).click();
    ok(await until(async () => (await rows()) > n0, 8000), `„Weitere laden“ erweitert die Liste (${n0} → ${await rows()})`);
  } else skip(`„Weitere laden“: nur ${all.length} CVEs (Seitengröße 100); UI-Pfad durch e2e-cves-toolbar.mjs mit erzeugten Zeilen abgedeckt`);
});

// ---- 4. Abruf-Läufe gegen den lokalen Mock ----------------------------------------------------------------------------
const mode = async (m) => (await fetch(`${MOCK}/__mode`, { method: "POST", body: JSON.stringify({ mode: m }) })).status;
const runsOf = async (src) => (await admin.call("GET", `/api/v1/feeds/runs?source=${src}&limit=5`)).json.runs;
const idle = async () => until(async () => (await admin.call("GET", "/api/v1/feeds/runs?active=true")).json.runs.every((r) => !["queued", "running"].includes(r.status)), 60000, 500);
const age = (mins) => sql(`UPDATE feed_runs SET created_at = now() - interval '${mins} minutes' WHERE source = 'debian'`);
async function finish(src, runId, ms = 60000) {
  return until(async () => { const r = (await runsOf(src)).find((x) => x.id === runId); return r && !["queued", "running"].includes(r.status) ? r : null; }, ms, 400);
}

await section("Abruf-Läufe (Debian-Quelle, Fehlermodi des Mocks)", async () => {
  ok((await mode("ok")) === 200, "Mock steuerbar (POST /__mode)");
  ok(await idle(), "kein Lauf aktiv zu Beginn");
  const feeds = (await admin.call("GET", "/api/v1/feeds")).json;
  ok(feeds.some((f) => f.source === "debian") && feeds.some((f) => f.source === "ubuntu"), "eingebaute Quellen debian und ubuntu vorhanden");
  ok(feeds.every((f) => !("secret" in f)), "Quellenliste ohne Geheimnisfeld");
  ok((await admin.call("POST", "/api/v1/feeds/gibtsnicht/run")).status === 404, "unbekannte Quelle: 404");

  // Erfolg (200) und 304
  age(60); await mode("fresh");
  const s1 = await admin.call("POST", "/api/v1/feeds/debian/run");
  ok(s1.status === 202 && s1.json?.run?.id > 0, "Abruf starten: 202 mit Lauf");
  const r1 = await finish("debian", s1.json.run.id);
  ok(r1?.status === "ok", `Lauf endet mit Erfolg (${r1?.status}${r1?.error ? ": " + r1.error : ""})`);
  const soon = await admin.call("POST", "/api/v1/feeds/debian/run");
  ok(soon.status === 429 && soon.json?.code === "too_soon" && Number(soon.headers.get("retry-after")) >= 1 && soon.json.retry_after >= 1, "zu früher zweiter Abruf: 429 too_soon mit Retry-After");
  age(60); await mode("ok");
  const s2 = await admin.call("POST", "/api/v1/feeds/debian/run");
  const r2 = await finish("debian", s2.json?.run?.id);
  ok(r2?.status === "not_modified", `Mock antwortet 304: Lauf „not_modified“ (${r2?.status})`);

  // 503 mit Retry-After: wartet die genannte Zeit, wiederholt, scheitert dann verständlich.
  age(60); await mode("503ra");
  const t0 = Date.now();
  const s3 = await admin.call("POST", "/api/v1/feeds/debian/run");
  const r3 = await finish("debian", s3.json?.run?.id);
  ok(r3?.status === "failed" && /503/.test(r3.error ?? ""), `503 mit Retry-After: Lauf „failed“, Fehlertext nennt 503 (${r3?.status}: ${r3?.error})`);
  ok((r3?.retries ?? 0) >= 1 && Date.now() - t0 >= 900, `Retry-After beachtet: ${r3?.retries} Wiederholung(en), ${Date.now() - t0} ms`);
  const fs = (await admin.call("GET", "/api/v1/feeds")).json.find((f) => f.source === "debian");
  ok(fs.state === "stale" || fs.consecutive_failures > 0, `Quelle zeigt den Fehler (state=${fs.state}, Fehlläufe ${fs.consecutive_failures})`);
  ok(!/\bat \w+::|panicked/.test(fs.error_text ?? ""), "Fehlertext ist verständlich (keine Interna)");

  // Backoff: 429 (zu früh) → 428 (Bestätigung) → 429 backoff_limited → 202 mit confirm
  ok((await admin.call("POST", "/api/v1/feeds/debian/run")).status === 429, "direkt nach dem Fehlschlag: 429 too_soon");
  age(2);
  const b1 = await admin.call("POST", "/api/v1/feeds/debian/run");
  ok(b1.status === 428 && b1.json?.code === "backoff" && b1.json.failures >= 1, "im Backoff ohne Bestätigung: 428 backoff (mit Fehlversuchen)");
  const b2 = await admin.call("POST", "/api/v1/feeds/debian/run", { body: { confirm: true } });
  ok(b2.status === 429 && b2.json?.code === "backoff_limited" && Number(b2.headers.get("retry-after")) > 0, "mit Bestätigung, aber < 5 min seit letztem Abruf: 429 backoff_limited");
  age(10); await mode("503");
  const b3 = await admin.call("POST", "/api/v1/feeds/debian/run", { body: { confirm: true } });
  ok(b3.status === 202, "mit Bestätigung nach 5 min: 202");
  const r4 = await finish("debian", b3.json?.run?.id);
  ok(r4?.status === "failed" && /503/.test(r4.error ?? "") && (r4.retries ?? 0) >= 1, `503 ohne Retry-After: Lauf „failed“ nach Wiederholungen (${r4?.error})`);

  // 422: nicht wiederholbar
  age(10); await mode("422");
  const u1 = await admin.call("POST", "/api/v1/feeds/debian/run", { body: { confirm: true } });
  const r5 = await finish("debian", u1.json?.run?.id);
  ok(r5?.status === "failed" && /422/.test(r5.error ?? "") && (r5.retries ?? 0) === 0, `422: „failed“ ohne Wiederholung (${r5?.error}, Wiederholungen ${r5?.retries})`);

  // Zeitüberschreitung und 409 bei laufendem Lauf (Mock antwortet nicht)
  age(10); await mode("hang");
  const h1 = await admin.call("POST", "/api/v1/feeds/debian/run", { body: { confirm: true } });
  ok(h1.status === 202, "Abruf gegen hängenden Mock gestartet: 202");
  await sleep(500);
  const h2 = await admin.call("POST", "/api/v1/feeds/debian/run", { body: { confirm: true } });
  ok(h2.status === 409 && h2.json?.code === "running" && h2.json.run_id === h1.json.run.id, "zweiter Abruf bei laufendem Lauf: 409 mit run_id des laufenden Laufs");
  const ra = await admin.call("POST", "/api/v1/feeds/refresh", { body: { confirm: true } });
  ok((ra.status === 202 || ra.status === 409) && JSON.stringify(ra.json).includes(String(h1.json.run.id)), `„Alle abrufen“ während des Laufs: ${ra.status}, nennt den laufenden Lauf`);
  const timeoutCfg = (await finish("debian", h1.json.run.id, 45000));
  if (timeoutCfg) {
    const secs = (Date.parse(timeoutCfg.finished_at) - Date.parse(timeoutCfg.started_at)) / 1000;
    ok(timeoutCfg.status === "failed" && /(Netzwerkfehler|Zeit)/i.test(timeoutCfg.error ?? "") && secs >= 3, `Zeitüberschreitung: „failed“ nach ${secs.toFixed(1)} s (2 Versuche à 2 s), Fehlertext „${timeoutCfg.error}“`);
    const ft = (await admin.call("GET", "/api/v1/feeds")).json.find((f) => f.source === "debian");
    ok(/Verbindung zu Debian fehlgeschlagen/.test(ft.error_text ?? ""), `Quellenliste zeigt verständlichen Text („${ft.error_text}“)`);
  }
  else { ok(false, "Lauf gegen hängenden Mock endete nicht binnen 45 s (Server ohne PATCHWATCH_CONFIG mit request_timeout_secs = 2?)"); }
  await idle(); await mode("ok");

  // Erholung und „Alle abrufen“
  age(10); await mode("fresh");
  const e1 = await admin.call("POST", "/api/v1/feeds/debian/run", { body: { confirm: true } });
  const r6 = await finish("debian", e1.json?.run?.id);
  ok(r6?.status === "ok", `nach Erholung wieder Erfolg (${r6?.status})`);
  const fs2 = (await admin.call("GET", "/api/v1/feeds")).json.find((f) => f.source === "debian");
  ok(fs2.consecutive_failures === 0 && fs2.state !== "stale", `Fehlerzähler zurückgesetzt (state=${fs2.state})`);
  sql("UPDATE feed_runs SET created_at = now() - interval '10 minutes'"); await mode("ok");
  const all = await admin.call("POST", "/api/v1/feeds/refresh");
  ok(all.status === 202 && all.json.runs.length >= 1, `„Alle abrufen“: 202 mit ${all.json?.runs?.length} Läufen`);
  ok(await idle(), "alle Läufe enden");
  const again = await admin.call("POST", "/api/v1/feeds/refresh");
  ok(again.status === 202 && again.json.runs.length === 0 && again.json.skipped.length >= 1 && again.json.skipped.every((s) => s.reason === "too_soon"), "„Alle abrufen“ direkt danach: nichts gestartet, Quellen als too_soon übersprungen");
  const fin = (await admin.call("GET", "/api/v1/feeds/runs?limit=10")).json.runs.filter((r) => r.trigger === "manual").slice(0, 2);
  ok(fin.every((r) => ["ok", "not_modified", "incomplete"].includes(r.status)), `Läufe von „Alle abrufen“ erfolgreich (${fin.map((r) => r.status).join(", ")})`);
  await mode("ok");
});

// ---- 5. Quellenverwaltung ---------------------------------------------------------------------------------------------
await section("Quellenverwaltung", async () => {
  const feeds = async () => (await admin.call("GET", "/api/v1/feeds")).json;
  const HTML = `<b>Spiegel</b> & "x" '<img src=x onerror=alert(1)>`;
  const cr = await admin.call("POST", "/api/v1/feeds", { body: { type: "osv", label: HTML.slice(0, 40), ecosystem: "Debian:13" } });
  ok(cr.status === 201 && cr.json?.id, `Quelle anlegen (osv, Ökosystem Debian:13): 201 (${cr.status} ${cr.text.slice(0, 80)})`);
  const id = cr.json?.id;
  ok((await admin.call("POST", "/api/v1/feeds", { body: { type: "osv", label: HTML.slice(0, 40), ecosystem: "Ubuntu:24.04" } })).status === 409, "Duplikat (Name): 409");
  ok((await admin.call("POST", "/api/v1/feeds", { body: { type: "osv", label: "andere", ecosystem: "Debian:13" } })).status === 409, "Duplikat (gleiche Konfiguration): 409");
  ok((await admin.call("POST", "/api/v1/feeds", { body: { type: "osv", label: "x".repeat(41) } })).status === 400, "Name > 40 Zeichen: 400");
  ok((await admin.call("POST", "/api/v1/feeds", { body: { type: "osv", label: "a\nb" } })).status === 400, "Name mit Zeilenumbruch: 400");
  ok((await admin.call("POST", "/api/v1/feeds", { body: { type: "gibtsnicht" } })).status === 400, "unbekannter Typ: 400");
  ok([400, 422].includes((await admin.call("POST", "/api/v1/feeds", { body: { type: "osv", label: "zz", extra: 1 } })).status), "unbekanntes Feld wird abgelehnt");
  // SSRF-Schutz: lokale und interne Ziele werden abgelehnt (der Schutz bleibt unverändert).
  const targets = [MOCK, "http://localhost:8190", "http://127.0.0.1:1", "http://[::1]/", "http://169.254.169.254/latest", "http://10.0.0.1/", "http://192.168.1.1/", "http://0.0.0.0/", "file:///etc/passwd", "ftp://example.org/", "http://user:pw@example.org/", "http://127.1/", "http://2130706433/"];
  let accepted = [];
  for (const t of targets) {
    const r = await admin.call("POST", "/api/v1/feeds", { body: { type: "nvd", label: `ssrf-${accepted.length}`, base_url: t } });
    if (r.status < 300) { accepted.push(t); await admin.call("DELETE", `/api/v1/feeds/${r.json.id}`); }
  }
  ok(accepted.length === 0, `Loopback-, private, Metadaten- und Nicht-HTTP-Ziele werden abgelehnt${accepted.length ? " (ANGENOMMEN: " + accepted.join(", ") + ")" : ""}`);
  ok((await admin.call("PUT", `/api/v1/feeds/${id}`, { body: { base_url: MOCK } })).status === 400, "Ändern auf Loopback-Adresse: 400");
  console.log("INFO Annahme eines öffentlichen Ziels nicht getestet (bräuchte DNS/Internet); siehe Rust-Tests server/tests/cve.rs und src/notify/ssrf.rs");

  // HTML im Namen: Anzeige als Text.
  const p = await ui(); await p.goto(`${WEB}/cves`);
  const table = p.getByRole("table", { name: "Zustand der CVE-Quellen" }); await table.waitFor();
  ok((await table.innerText()).includes("<b>Spiegel</b>") && (await table.locator("b, img[src='x']").count()) === 0, "Name mit HTML wird als Text angezeigt (kein Element erzeugt)");
  const dialogs = []; p.on("dialog", (d) => { dialogs.push(d.message()); d.dismiss(); });
  await p.reload(); await table.waitFor(); await sleep(500);
  ok(dialogs.length === 0, "kein Skript aus dem Quellennamen ausgeführt");

  // Abschalten: Hosts der Distribution zeigen „CVE-Lage unbekannt“, nie grün.
  const hosts = async () => (await admin.call("GET", "/api/v1/hosts")).json;
  const byName = (hs, n) => hs.find((h) => h.name === n);
  const before = await hosts();
  ok(byName(before, "web-01")?.status !== "cve_unknown", `Ausgangslage: web-01 nicht „unbekannt“ (${byName(before, "web-01")?.status})`);
  ok((await admin.call("PUT", "/api/v1/feeds/ubuntu", { body: { enabled: false } })).status === 204, "Ubuntu abschalten: 204");
  // Dringlichere Zustände (z. B. Sicherheitsupdates) gehen im Gesamtstatus vor; „unbekannt“ steht dann in cve_unknown (Anzahl).
  const UB = ["web-01", "web-02", "backup-01"];
  const isUnk = (h) => h.status === "cve_unknown" || h.cve_unknown > 0;
  const unk = await until(async () => { const hs = await hosts(); return UB.every((n) => isUnk(byName(hs, n)) && byName(hs, n).cve_vulnerable === 0 && byName(hs, n).cve_fix_pending === 0) ? hs : null; }, 40000); // Neubewertung läuft im Hintergrund
  const hs = unk ?? await hosts();
  ok(!!unk, `Ubuntu-Hosts: CVE-Lage unbekannt, keine Ubuntu-CVE als verwundbar behauptet (${UB.map((n) => `${byName(hs, n).status}/${byName(hs, n).cve_unknown}`).join(", ")})`);
  ok(hs.every((h) => !UB.includes(h.name) || h.status !== "ok"), "kein Ubuntu-Host grün");
  await p.goto(`${WEB}/`);
  const row = p.getByRole("row").filter({ hasText: "web-01" }).first(); await row.waitFor();
  ok(/Nicht bewertbar/.test(await row.innerText()), "Oberfläche: web-01 zeigt „Nicht bewertbar“ (Text, nicht nur Farbe)");
  ok((await admin.call("POST", "/api/v1/feeds/ubuntu/run")).status === 400, "Abruf einer abgeschalteten Quelle: 400");
  ok((await admin.call("PUT", "/api/v1/feeds/ubuntu", { body: { enabled: true } })).status === 204, "Ubuntu einschalten: 204");
  const back = await until(async () => { const h2 = await hosts(); return ["web-01", "web-02"].every((n) => byName(h2, n).cve_unknown <= byName(before, n).cve_unknown) ? h2 : null; }, 30000);
  ok(!!back, `nach dem Einschalten bewertet der Server die Ubuntu-Hosts wieder (${back ? byName(back, "web-01").status : "weiter unbekannt"})`);

  // Löschen der verwalteten Quelle und der eingebauten Debian-Quelle (Folgen für Hosts).
  ok((await admin.call("DELETE", `/api/v1/feeds/${id}`)).status === 204, "verwaltete Quelle löschen: 204");
  ok(!(await feeds()).some((f) => f.source === id), "gelöschte Quelle fehlt in der Liste");
  ok((await admin.call("DELETE", `/api/v1/feeds/${id}`)).status === 404, "erneut löschen: 404");
  ok((await admin.call("DELETE", "/api/v1/feeds/debian")).status === 204, "Debian-Quelle löschen: 204");
  const gone = await until(async () => { const h3 = await hosts(); return ["db-01", "db-02"].every((n) => isUnk(byName(h3, n))) ? h3 : null; }, 30000);
  ok(!!gone && gone.every((h) => !["db-01", "db-02", "pve-01"].includes(h.name) || h.status !== "ok"), `ohne Debian-Quelle sind Debian-Hosts „CVE-Lage unbekannt“, nie grün (${["db-01", "db-02", "pve-01"].map((n) => `${byName(gone ?? [], n)?.status}/${byName(gone ?? [], n)?.cve_unknown}`).join(", ")})`);
  ok(byName(gone ?? [], "pve-01")?.status !== "ok", "Proxmox-Host nie grün");
  console.log("INFO Debian-Quelle ist gelöscht: Seed-Zustand mit `scripts/dev-stack.sh down && up` wiederherstellen");
});

// ---- 6. Benachrichtigungskanäle -----------------------------------------------------------------------------------------
await section("Benachrichtigungskanäle", async () => {
  const lst = await admin.call("GET", "/api/v1/notifications");
  ok(lst.status === 200 && Array.isArray(lst.json?.channels), "Kanalliste");
  const SECRET = `Tok-${randomBytes(12).toString("hex")}`;
  if (!lst.json.secret_storage) { skip("Geheimnis-Speicherung: Server ohne PATCHWATCH_SECRET_KEY; Abdeckung: server/tests/notify.rs (secrets_are_write_only_and_encrypted_at_rest)"); }
  else {
    const events = lst.json.events.slice(0, 2);
    const put = await admin.call("PUT", "/api/v1/notifications/gotify", { body: { enabled: false, config: { url: "https://gotify.example.org" }, secret: SECRET, events } });
    ok(put.status === 200 && put.json?.secret_set === true, `Geheimnis speichern: Antwort nur „secret_set: true“ (${put.status} ${put.status !== 200 ? put.text.slice(0, 100) : ""})`);
    ok(!leaks(put.text, SECRET), "Antwort enthält das Geheimnis nicht");
    const g1 = await admin.call("GET", "/api/v1/notifications/gotify"), g2 = await admin.call("GET", "/api/v1/notifications");
    ok(!leaks(g1.text, SECRET) && !leaks(g2.text, SECRET) && g1.json.secret_set === true, "GET liefert nur „gesetzt“, nie das Geheimnis");
    ok(JSON.stringify(g1.json.events) === JSON.stringify(events), "Ereignisauswahl gespeichert und gelesen");
    const keep = await admin.call("PUT", "/api/v1/notifications/gotify", { body: { enabled: false, config: { url: "https://gotify.example.org" }, events: lst.json.events } });
    ok(keep.json?.secret_set === true && keep.json.events.length === lst.json.events.length, "Speichern ohne Geheimnis behält das gespeicherte; alle Ereignisse wählbar");
    ok((await admin.call("PUT", "/api/v1/notifications/gotify", { body: { enabled: false, events: ["gibtsnicht"] } })).status === 400, "unbekannte Ereignisart: 400");
    ok((await admin.call("PUT", "/api/v1/notifications/gibtsnicht", { body: { enabled: false } })).status === 404, "unbekannter Kanal: 404");
    ok(!leaks(JSON.stringify((await admin.call("GET", "/api/v1/settings")).json ?? {}), SECRET), "Einstellungen enthalten das Geheimnis nicht");
    if (sql("SELECT count(*) FROM information_schema.tables WHERE table_name = 'notification_channels'") === "1") {
      ok(sql("SELECT count(*) FROM notification_channels WHERE kind = 'gotify' AND secret IS NOT NULL") === "1" && sql(`SELECT count(*) FROM notification_channels WHERE secret::text LIKE '%${SECRET}%'`) === "0", "in der Datenbank nur verschlüsselt (kein Klartext)");
    }
    await admin.call("PUT", "/api/v1/notifications/gotify", { body: { enabled: false, clear_secret: true, events } });
  }
  // Testnachricht an Loopback: abgelehnt, und es kommt keine Verbindung am lokalen Empfänger an.
  let hits = 0;
  const srv = createServer((s) => { hits++; s.destroy(); });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const port = srv.address().port;
  const lp = await admin.call("PUT", "/api/v1/notifications/webhook", { body: { enabled: true, config: { url: `http://127.0.0.1:${port}/hook` }, events: [] } });
  if (lp.status >= 400) ok(true, `Loopback-Ziel schon beim Speichern abgelehnt (${lp.status})`);
  const t = await admin.call("POST", "/api/v1/notifications/webhook/test");
  ok(t.status >= 400 || (t.json && t.json.ok === false), `Testnachricht an Loopback abgelehnt (${t.status} ${JSON.stringify(t.json)})`);
  const meta = await admin.call("PUT", "/api/v1/notifications/webhook", { body: { enabled: true, config: { url: "http://169.254.169.254/x" }, events: [] } });
  const t2 = await admin.call("POST", "/api/v1/notifications/webhook/test");
  ok(meta.status >= 400 || t2.status >= 400 || t2.json?.ok === false, "Testnachricht an die Metadaten-IP abgelehnt");
  await sleep(300);
  ok(hits === 0, `am lokalen Empfänger ist keine Verbindung angekommen (${hits})`);
  srv.close();
  await admin.call("PUT", "/api/v1/notifications/webhook", { body: { enabled: false, config: {}, events: [] } });
  console.log("INFO Zustellung an ein Ziel: nur über die Rust-Tests server/tests/notify.rs (Loopback ist gesperrt und bleibt es: notify_job_delivers_and_records_generic_error, channel_formats_and_generic_errors, loopback_and_metadata_targets_are_blocked_even_when_allowlisted)");
});

// ---- 7. Live-Updates (WebSocket) ----------------------------------------------------------------------------------------
await section("Live-Updates (WebSocket)", async () => {
  const ws = (cookie, origin) => new Promise((resolve) => {
    const u = new URL(API + "/api/v1/live");
    const key = randomBytes(16).toString("base64");
    const headers = { Connection: "Upgrade", Upgrade: "websocket", "Sec-WebSocket-Version": "13", "Sec-WebSocket-Key": key };
    if (cookie) headers.cookie = cookie; if (origin) headers.origin = origin;
    const req = httpRequest({ host: u.hostname, port: u.port, path: u.pathname, headers });
    req.on("response", (res) => { res.resume(); resolve({ status: res.statusCode }); });
    req.on("upgrade", (res, socket) => { resolve({ status: res.statusCode, socket }); });
    req.on("error", () => resolve({ status: 0 }));
    req.end();
  });
  const goodOrigin = WEB;
  ok((await ws(null, goodOrigin)).status === 401, "WebSocket ohne Session: 401");
  const bad = await ws(admin.cookie, "http://evil.example"); ok(bad.status === 403, `WebSocket mit falscher Origin: 403 (${bad.status})`);
  const good = await ws(admin.cookie, goodOrigin);
  ok(good.status === 101, `WebSocket mit Session und passender Origin: verbunden (101, ${good.status})`);
  if (good.socket) {
    let buf = ""; good.socket.on("data", (d) => { buf += d.toString("latin1"); });
    const id = (await admin.call("GET", "/api/v1/hosts")).json.find((h) => h.name === "web-02").id;
    sql(`UPDATE hosts SET last_report_request_at = NULL WHERE id = ${id}`);
    await admin.call("POST", `/api/v1/hosts/${id}/request-report`);
    ok(await until(() => buf.includes("report_requested"), 6000, 200), "Ereignis „report_requested“ kommt live an");
    sql("UPDATE hosts SET report_requested_at = NULL, report_dispatched_at = NULL");
    good.socket.destroy();
  }
  console.log("INFO Toasts: scripts/e2e-toasts.mjs; Sitzungsprüfung, Limit 64 Verbindungen und Nachrichten vom Client: server/tests/live.rs");
});

// ---- 8. Profilbild (API) --------------------------------------------------------------------------------------------------
await section("Profilbild: Ablehnungen und Entfernen (gültiges Bild: e2e-avatar.mjs, server/tests/avatar.rs)", async () => {
  const put = (data, type) => admin.call("PUT", "/api/v1/auth/avatar", { raw: data, headers: { "content-type": type } });
  const svg = '<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128"><script>alert(1)</script></svg>';
  ok((await put(svg, "image/svg+xml")).status === 400, "SVG: 400");
  ok((await put(svg, "image/png")).status === 400, "SVG als image/png getarnt: 400");
  const big = await put(Buffer.alloc(200000, 7), "image/png");
  ok(big.status === 400 || big.status === 413, `zu große Datei: abgelehnt (${big.status})`);
  ok((await put(Buffer.from("PNG-kaputt"), "image/png")).status === 400, "kaputte Datei: 400");
  ok((await put(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0]), "image/png")).status === 400, "PNG-Kopf ohne Inhalt: 400");
  ok((await new Session().call("GET", "/api/v1/auth/avatar")).status === 401, "ohne Anmeldung: 401");
  ok([204, 200].includes((await admin.call("DELETE", "/api/v1/auth/avatar")).status), "Entfernen: Erfolg");
  ok((await admin.call("GET", "/api/v1/auth/avatar")).status === 404, "danach: 404 (Initialen)");
});

// ---- 9. Sperre nach 10 Versuchen (zuletzt: danach ist die Anmeldung gesperrt) ----------------------------------------
await section("Anmelde-Sperre nach 10 Fehlversuchen", async () => {
  // Das Limit zählt alle Anmeldeversuche je IP (auch erfolgreiche) seit dem Serverstart: 10 pro 10 Minuten.
  const s = new Session(); let last; const before = loginAttempts;
  for (let i = 0; i < 14; i++) { last = await s.login(USER, `falsch-${i}-falsch-falsch`); if (last.status === 429) { ok(loginAttempts - 1 === 10, `Sperre ab dem 11. Anmeldeversuch seit dem Serverstart (bei ${loginAttempts}; vorher im Test ${before})`); break; } }
  ok(last.status === 429 && Number(last.headers.get("retry-after")) >= 1, `429 mit Retry-After (${last.headers.get("retry-after")} s)`);
  const right = await new Session().login(USER, PW);
  ok(right.status === 429, "auch das richtige Passwort wird während der Sperre abgelehnt (429)");
  console.log("INFO Server wird neu gestartet, um das Login-Limit zurückzusetzen");
  const root = new URL("..", import.meta.url).pathname;
  const r = spawnSync(join(root, "scripts/dev-stack.sh"), ["restart-server"], { encoding: "utf8", timeout: 120000 });
  ok(r.status === 0, `restart-server (${r.status})`);
  ok((await new Session().login(USER, PW)).status === 200, "nach dem Neustart: Anmeldung wieder möglich");
});

if (browser) await browser.close();
console.log(fails ? `\n${fails} FEHLER` : "\nalles bestanden");
