"use client";

import { useState } from "react";
import { api, ApiError } from "@/lib/api";
import { Button, Field, TextInput } from "@/components/Controls";
import { ErrorNote } from "@/components/States";

const MIN_LEN = 12;

/**
 * Zwangswechsel des Start-Passworts: Der Server lässt mit so einem Konto nur Passwortwechsel und Abmelden zu;
 * die App zeigt deshalb nur dieses Formular, bis das Passwort geändert ist.
 */
export function ForcedPasswordChange({ username, onDone, onLogout }: { username: string; onDone: () => void; onLogout: () => void }) {
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
      await api.post("/auth/password", { current_password: current, new_password: next });
      onDone();
    } catch (err) {
      setError(err instanceof ApiError ? (err.status === 429 ? `Zu viele Versuche. Erneut möglich in ${err.retryAfter ?? 60} Sek.` : err.message) : "Passwort konnte nicht geändert werden.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main id="main" tabIndex={-1} className="mx-auto flex min-h-dvh max-w-sm flex-col justify-center px-4">
      <h1 className="mb-1 font-mono text-xl font-medium">patchwatch</h1>
      <p className="mb-1 text-fg2">Passwort ändern</p>
      <p className="mb-5 text-fg3">
        Das Konto <span className="font-mono">{username}</span> nutzt ein Start-Passwort. Bitte jetzt ein eigenes wählen, vorher ist nichts anderes möglich.
      </p>
      <form onSubmit={(e) => void submit(e)} className="flex flex-col gap-3 border border-line bg-surface p-4">
        <Field label="Aktuelles (Start-)Passwort">
          <TextInput type="password" value={current} onChange={(e) => setCurrent(e.target.value)} autoComplete="current-password" required maxLength={256} />
        </Field>
        <Field label={`Neues Passwort (mindestens ${MIN_LEN} Zeichen)`}>
          <TextInput type="password" value={next} onChange={(e) => setNext(e.target.value)} autoComplete="new-password" required maxLength={256} />
        </Field>
        <Field label="Neues Passwort wiederholen">
          <TextInput type="password" value={again} onChange={(e) => setAgain(e.target.value)} autoComplete="new-password" required maxLength={256} />
        </Field>
        {error ? <ErrorNote message={error} /> : null}
        <Button type="submit" variant="primary" busy={busy} disabled={!current || !next || !again}>
          Passwort ändern
        </Button>
      </form>
      <button type="button" onClick={onLogout} className="mt-3 self-start text-fg2 underline">
        Abmelden
      </button>
    </main>
  );
}
