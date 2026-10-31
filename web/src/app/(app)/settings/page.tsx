"use client";

import { useState } from "react";
import { api, ApiError } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import type { Settings } from "@/lib/types";
import { useAuth } from "@/components/AuthProvider";
import { Button, Field, TextInput } from "@/components/Controls";
import { PageHeader } from "@/components/PageHeader";
import { ErrorNote, Loading } from "@/components/States";
import { ThemeSelect } from "@/components/ThemeSelect";
import { Mono } from "@/components/Version";

const MIN_LEN = 12;

function PasswordForm() {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [again, setAgain] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setDone(false);
    if (next.length < MIN_LEN) return setError(`Das neue Passwort braucht mindestens ${MIN_LEN} Zeichen.`);
    if (next !== again) return setError("Die beiden neuen Passwörter stimmen nicht überein.");
    setBusy(true);
    setError(null);
    try {
      await api.post("/auth/password", { current_password: current, new_password: next });
      setCurrent("");
      setNext("");
      setAgain("");
      setDone(true);
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
      {done ? (
        <p role="status" className="text-ok">
          Passwort geändert. Alle anderen Sitzungen wurden abgemeldet.
        </p>
      ) : null}
      <Button type="submit" variant="primary" disabled={busy || !current || !next || !again} className="self-start">
        {busy ? "Ändere …" : "Passwort ändern"}
      </Button>
    </form>
  );
}

function Retention() {
  const s = useApi<Settings>("/settings");
  const [value, setValue] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  if (s.error && !s.data) return <ErrorNote message={s.error} />;
  if (!s.data) return <Loading what="Einstellungen" />;
  const { report_retention_days: days, report_retention_min_days: min, report_retention_max_days: max, report_retention_default_days: def } = s.data;
  const shown = value ?? String(days);

  async function save(e: React.FormEvent) {
    e.preventDefault();
    const n = Number(shown);
    setDone(false);
    if (!Number.isInteger(n) || n < min || n > max) return setError(`Bitte eine ganze Zahl zwischen ${min} und ${max} eingeben.`);
    setBusy(true);
    setError(null);
    try {
      await api.put("/settings", { report_retention_days: n });
      setValue(null);
      setDone(true);
      await s.reload();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Einstellung konnte nicht gespeichert werden.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={(e) => void save(e)} className="flex max-w-sm flex-col gap-3">
      <Field label="Report-Historie aufbewahren (Tage)">
        <TextInput type="number" inputMode="numeric" min={min} max={max} value={shown} onChange={(e) => setValue(e.target.value)} className="w-32" required />
      </Field>
      <p className="text-xs text-fg3">
        Ältere Reports löscht der tägliche Aufräum-Job. Erlaubt: {min} bis {max} Tage. Standard der Server-Konfiguration: {def} Tage (<Mono>PATCHWATCH_REPORT_RETENTION_DAYS</Mono>).
      </p>
      {error ? <ErrorNote message={error} /> : null}
      {done ? (
        <p role="status" className="text-ok">
          Gespeichert.
        </p>
      ) : null}
      <Button type="submit" variant="primary" disabled={busy || value === null || value === String(days)} className="self-start">
        {busy ? "Speichere …" : "Speichern"}
      </Button>
    </form>
  );
}

export default function SettingsPage() {
  const { me } = useAuth();
  return (
    <>
      <PageHeader title="Einstellungen" />

      <section aria-labelledby="acct-h" className="mb-8">
        <h2 id="acct-h" className="mb-1 text-lg font-semibold">
          Konto
        </h2>
        <p className="mb-3 text-fg2">
          Angemeldet als <Mono>{me.username}</Mono>.
        </p>
        <PasswordForm />
      </section>

      <section aria-labelledby="look-h" className="mb-8">
        <h2 id="look-h" className="mb-2 text-lg font-semibold">
          Darstellung
        </h2>
        <ThemeSelect />
        <p className="mt-1 max-w-prose text-xs text-fg3">„System“ folgt der Einstellung deines Geräts. Die Auswahl wird nur in diesem Browser gemerkt.</p>
      </section>

      <section aria-labelledby="data-h">
        <h2 id="data-h" className="mb-2 text-lg font-semibold">
          Daten
        </h2>
        <Retention />
      </section>
    </>
  );
}
