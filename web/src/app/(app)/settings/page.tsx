"use client";

import { useState } from "react";
import { api, ApiError } from "@/lib/api";
import { toast } from "@/lib/toastStore";
import { useApi } from "@/lib/useApi";
import type { Settings } from "@/lib/types";
import { useAuth } from "@/components/AuthProvider";
import { Button, Field, Select, TextInput } from "@/components/Controls";
import { SettingsSection } from "@/components/SettingsSection";
import { PageHeader } from "@/components/PageHeader";
import { ErrorNote, Loading } from "@/components/States";
import { ThemeSelect } from "@/components/ThemeSelect";
import { RelTime } from "@/components/RelTime";
import { Mono } from "@/components/Version";
import { AvatarForm } from "@/components/AvatarForm";
import { OidcSettings } from "@/components/users/OidcSettings";
import { can, type RolesResponse } from "@/lib/roles";

const MIN_LEN = 12;

/** Konto: Anzeigename ändern (vor allem bei OIDC, wo der Anbieter den Namen vorgibt). Der Anmeldename bleibt unverändert. */
function ProfileForm() {
  const { me, setDisplayName } = useAuth();
  const current = me.display_name || me.username;
  const [name, setName] = useState(current);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const trimmed = name.trim();

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const r = await api.put<{ display_name: string }>("/auth/profile", { display_name: trimmed }, { silent: true });
      setDisplayName(r.display_name);
      setName(r.display_name);
      toast.success("Anzeigename gespeichert.");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Anzeigename konnte nicht gespeichert werden.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={(e) => void submit(e)} className="flex max-w-sm flex-col gap-3">
      <Field label="Anzeigename (1 bis 60 Zeichen)">
        <TextInput value={name} onChange={(e) => setName(e.target.value)} autoComplete="nickname" required maxLength={60} />
      </Field>
      {error ? <ErrorNote message={error} /> : null}
      <Button type="submit" variant="primary" busy={busy} disabled={!trimmed || trimmed === current} className="self-start">
        Namen speichern
      </Button>
    </form>
  );
}

function PasswordForm() {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [again, setAgain] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (next.length < MIN_LEN) return setError(`Das neue Passwort braucht mindestens ${MIN_LEN} Zeichen.`);
    if (next !== again) return setError("Die beiden neuen Passwörter stimmen nicht überein.");
    setBusy(true);
    setError(null);
    try {
      await api.post("/auth/password", { current_password: current, new_password: next }, { silent: true });
      setCurrent("");
      setNext("");
      setAgain("");
      toast.success("Passwort geändert. Alle anderen Sitzungen wurden abgemeldet.");
    } catch (err) {
      setError(err instanceof ApiError ? (err.status === 429 ? `Zu viele Versuche. Erneut möglich in ${err.retryAfter ?? 60} Sek.` : err.message) : "Passwort konnte nicht geändert werden.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={(e) => void submit(e)} className="flex max-w-sm flex-col gap-3">
      <Field label="Aktuelles Passwort">
        <TextInput type="password" value={current} onChange={(e) => setCurrent(e.target.value)} autoComplete="current-password" required maxLength={256} />
      </Field>
      <Field label={`Neues Passwort (mindestens ${MIN_LEN} Zeichen)`}>
        <TextInput type="password" value={next} onChange={(e) => setNext(e.target.value)} autoComplete="new-password" required maxLength={256} />
      </Field>
      <Field label="Neues Passwort wiederholen">
        <TextInput type="password" value={again} onChange={(e) => setAgain(e.target.value)} autoComplete="new-password" required maxLength={256} />
      </Field>
      {error ? <ErrorNote message={error} /> : null}
      <Button type="submit" variant="primary" busy={busy} disabled={!current || !next || !again} className="self-start">
        Passwort ändern
      </Button>
    </form>
  );
}

/** Zeitpläne: Feed-Intervalle, Report-Anforderung des Servers, "meldet sich nicht", Aufbewahrung. Ein Speichern für alles. */
function Schedules() {
  const s = useApi<Settings>("/settings");
  const [edit, setEdit] = useState<Partial<Record<string, string>>>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (s.error && !s.data) return <ErrorNote message={s.error} />;
  if (!s.data) return <Loading what="Einstellungen" />;
  const d = s.data;
  const rs = d.report_schedule;
  const val = (k: string, base: string | number) => edit[k] ?? String(base);
  const set = (k: string) => (e: { target: { value: string } }) => {
    setEdit((x) => ({ ...x, [k]: e.target.value }));
  };
  const mode = val("mode", rs.mode);
  const dirty = Object.keys(edit).length > 0;

  function int(label: string, raw: string, min: number, max: number): number {
    const n = Number(raw);
    if (!Number.isInteger(n) || n < min || n > max) throw new Error(`${label}: bitte eine ganze Zahl zwischen ${min} und ${max} eingeben.`);
    return n;
  }

  async function save(e: React.FormEvent) {
    e.preventDefault();
    try {
      const body: Record<string, unknown> = {};
      const feed_intervals: Record<string, number> = {};
      for (const f of d.feeds) {
        if (edit[`feed.${f.source}`] !== undefined) feed_intervals[f.source] = int(`Feed ${f.label}`, edit[`feed.${f.source}`]!, d.feed_interval_min_minutes, d.feed_interval_max_minutes);
      }
      if (Object.keys(feed_intervals).length) body.feed_intervals = feed_intervals;
      const feed_bulk_intervals: Record<string, number> = {};
      for (const f of d.feeds) {
        if (f.bulk_interval_minutes !== null && edit[`bulk.${f.source}`] !== undefined) feed_bulk_intervals[f.source] = int(`Massendaten ${f.label}`, edit[`bulk.${f.source}`]!, d.feed_interval_min_minutes, d.feed_interval_max_minutes);
      }
      if (Object.keys(feed_bulk_intervals).length) body.feed_bulk_intervals = feed_bulk_intervals;
      if (edit.stale !== undefined) body.stale_after_hours = int("Meldet sich nicht", edit.stale, d.stale_after_min_hours, d.stale_after_max_hours);
      if (edit.retention !== undefined) body.report_retention_days = int("Aufbewahrung", edit.retention, d.report_retention_min_days, d.report_retention_max_days);
      if (["mode", "every", "at", "tz"].some((k) => edit[k] !== undefined)) {
        if (mode === "interval") body.report_schedule = { mode, every_hours: int("Abruf-Intervall", val("every", rs.mode === "interval" ? rs.every_hours : 24), d.report_every_hours_min, d.report_every_hours_max) };
        else if (mode === "daily") body.report_schedule = { mode, at: val("at", rs.mode === "daily" ? rs.at : "04:00"), tz: val("tz", rs.mode === "daily" ? rs.tz : Intl.DateTimeFormat().resolvedOptions().timeZone) };
        else body.report_schedule = { mode: "off" };
      }
      setBusy(true);
      setError(null);
      await api.put("/settings", body);
      setEdit({});
      toast.success("Einstellungen gespeichert.");
      await s.reload();
    } catch (err) {
      // Serverfehler zeigt der API-Client als Toast; hier bleiben nur Feldfehler der Eingabeprüfung.
      if (!(err instanceof ApiError)) setError(err instanceof Error ? err.message : "Einstellungen konnten nicht gespeichert werden.");
    } finally {
      setBusy(false);
    }
  }

  const num = "w-28";
  return (
    <form onSubmit={(e) => void save(e)} className="flex max-w-[45rem] flex-col gap-5">
      <fieldset className="flex flex-col gap-3">
        <legend className="mb-1 font-semibold">CVE-Feeds abrufen</legend>
        <div className="flex flex-wrap gap-3">
          {d.feeds.map((f) => (
            <Field key={f.source} label={`${f.label} (Minuten)`}>
              <TextInput type="number" inputMode="numeric" min={d.feed_interval_min_minutes} max={d.feed_interval_max_minutes} value={val(`feed.${f.source}`, f.interval_minutes)} onChange={set(`feed.${f.source}`)} className={num} />
            </Field>
          ))}
          {d.feeds.filter((f) => f.bulk_interval_minutes !== null).map((f) => (
            <Field key={`bulk.${f.source}`} label={`${f.label}: Massendaten-Import (Minuten)`}>
              <TextInput type="number" inputMode="numeric" min={d.feed_interval_min_minutes} max={d.feed_interval_max_minutes} value={val(`bulk.${f.source}`, f.bulk_interval_minutes ?? 1440)} onChange={set(`bulk.${f.source}`)} className={num} />
            </Field>
          ))}
        </div>
        <p className="text-xs text-fg3">
          {d.feed_interval_min_minutes} bis {d.feed_interval_max_minutes} Minuten, Standard {d.feeds[0]?.default_minutes ?? 60}. Die Änderung gilt ohne Neustart beim nächsten Durchlauf.
        </p>
      </fieldset>

      <fieldset className="flex flex-col gap-3">
        <legend className="mb-1 font-semibold">Daten bei den Hosts abrufen</legend>
        <div className="flex flex-wrap items-end gap-3">
          <Field label="Zeitplan">
            <Select value={mode} onChange={set("mode")}>
              <option value="off">Aus (Agents melden nach eigenem Zeitplan)</option>
              <option value="interval">Alle N Stunden</option>
              <option value="daily">Täglich zu einer Uhrzeit</option>
            </Select>
          </Field>
          {mode === "interval" ? (
            <Field label="Stunden">
              <TextInput type="number" inputMode="numeric" min={d.report_every_hours_min} max={d.report_every_hours_max} value={val("every", rs.mode === "interval" ? rs.every_hours : 24)} onChange={set("every")} className={num} />
            </Field>
          ) : null}
          {mode === "daily" ? (
            <>
              <Field label="Uhrzeit">
                <TextInput type="time" value={val("at", rs.mode === "daily" ? rs.at : "04:00")} onChange={set("at")} className="w-32" />
              </Field>
              <Field label="Zeitzone">
                <TextInput value={val("tz", rs.mode === "daily" ? rs.tz : Intl.DateTimeFormat().resolvedOptions().timeZone)} onChange={set("tz")} className="w-52" maxLength={64} />
              </Field>
            </>
          ) : null}
        </div>
        <p className="text-xs text-fg3">
          Zur fälligen Zeit fordert der Server bei allen Hosts neue Daten an; die Agents melden sie dann sofort. Der tägliche Timer im Agent bleibt als Rückfall bestehen.
          {rs.last_run ? <> Letzte Anforderung: <RelTime iso={rs.last_run} />.</> : null}
        </p>
        <p className="text-xs text-fg3">{d.checkin_interval_hint}</p>
      </fieldset>

      <fieldset className="flex flex-col gap-3">
        <legend className="mb-1 font-semibold">Aufbewahrung und Meldeschwelle</legend>
        <div className="flex flex-wrap gap-3">
          <Field label="„Meldet sich nicht“ nach (Stunden)">
            <TextInput type="number" inputMode="numeric" min={d.stale_after_min_hours} max={d.stale_after_max_hours} value={val("stale", d.stale_after_hours)} onChange={set("stale")} className={num} />
          </Field>
          <Field label="Verlauf der Datenmeldungen aufbewahren (Tage)">
            <TextInput type="number" inputMode="numeric" min={d.report_retention_min_days} max={d.report_retention_max_days} value={val("retention", d.report_retention_days)} onChange={set("retention")} className={num} />
          </Field>
        </div>
        <p className="text-xs text-fg3">
          „Meldet sich nicht“: {d.stale_after_min_hours} bis {d.stale_after_max_hours} Stunden, Standard {d.stale_after_default_hours} (<Mono>PATCHWATCH_STALE_AFTER_HOURS</Mono>). Aufbewahrung: {d.report_retention_min_days} bis {d.report_retention_max_days} Tage, Standard {d.report_retention_default_days}. Ältere Datenmeldungen löscht der tägliche Aufräum-Job.
        </p>
      </fieldset>

      {error ? <ErrorNote message={error} /> : null}
      <Button type="submit" variant="primary" busy={busy} disabled={!dirty} className="self-start">
        Speichern
      </Button>
    </form>
  );
}

export default function SettingsPage() {
  const { me } = useAuth();
  const canOidc = can(me.permissions, "oidc.manage");
  // Die Rollenliste (für Gruppe → Rolle) liefert der Server nur mit dem Recht zur Benutzerverwaltung; sonst gilt die feste Liste.
  const roles = useApi<RolesResponse>(canOidc && can(me.permissions, "users.manage") ? "/roles" : null);
  return (
    <>
      <PageHeader title="Einstellungen" />

      <SettingsSection id="acct-h" title="Konto" description={<>Angemeldet als <Mono>{me.username}</Mono>.</>}>
        <div className="flex flex-col gap-6">
          <ProfileForm />
          <AvatarForm />
          <PasswordForm />
        </div>
      </SettingsSection>

      <SettingsSection id="look-h" title="Darstellung" description="„System“ folgt der Einstellung deines Geräts. Die Auswahl wird nur in diesem Browser gemerkt.">
        <ThemeSelect />
      </SettingsSection>

      <SettingsSection id="sched-h" title="Zeitpläne" description="Abruf der CVE-Feeds, Datenabruf bei den Hosts und Schwellen. Änderungen gelten ohne Neustart.">
        <Schedules />
      </SettingsSection>

      <SettingsSection id="oidc" title="OIDC-Anmeldung" description="Anmeldung über einen OpenID-Connect-Anbieter (Authentik, Keycloak, Google, Entra …) zusätzlich zum Passwort.">
        {canOidc ? (
          <OidcSettings roles={roles.data} />
        ) : (
          <p role="note" className="m-0 max-w-prose border-l-4 border-line bg-sunk px-3 py-2 text-fg2">
            Die OIDC-Anmeldung einzurichten setzt das Recht „OIDC-Anmeldung einrichten“ voraus. Das hast du nicht; bitte einen Benutzer mit diesem Recht darum.
          </p>
        )}
      </SettingsSection>
    </>
  );
}
