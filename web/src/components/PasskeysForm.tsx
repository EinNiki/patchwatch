"use client";

import { useState } from "react";
import { api, ApiError } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { toast } from "@/lib/toastStore";
import { Button, Field, Switch, TextInput } from "@/components/Controls";
import { ErrorNote, Loading } from "@/components/States";
import { RelTime } from "@/components/RelTime";
import { createPasskey, passkeyErrorText, webauthnSupported } from "@/lib/webauthn";

interface PasskeyList {
  available: boolean;
  password_login_disabled: boolean;
  passkeys: { id: number; name: string; created_at: string; last_used_at: string | null }[];
}

/** Konto: eigene Passkeys anlegen und löschen; Anmeldung per Passwort für das eigene Konto ausschalten (nur mit Passkey). */
export function PasskeysForm() {
  const q = useApi<PasskeyList>("/auth/passkeys");
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!q.data) return q.error ? <ErrorNote message={q.error} /> : <Loading what="Passkeys" />;
  const d = q.data;

  async function add(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const start = await api.post<{ ceremony: string; options: { publicKey: Record<string, unknown> } }>("/auth/passkeys/register/start", {}, { silent: true });
      const credential = await createPasskey(start.options);
      await api.post("/auth/passkeys/register/finish", { ceremony: start.ceremony, name: name.trim() || "Dieses Gerät", credential }, { silent: true });
      setName("");
      toast.success("Passkey hinzugefügt.");
      await q.reload();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : passkeyErrorText(err));
    } finally {
      setBusy(false);
    }
  }

  async function remove(id: number) {
    try {
      await api.del(`/auth/passkeys/${id}`, { silent: true });
      toast.success("Passkey gelöscht.");
      await q.reload();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Löschen fehlgeschlagen.");
    }
  }

  async function togglePassword(disabled: boolean) {
    setError(null);
    try {
      await api.put("/auth/password-login", { disabled }, { silent: true });
      await q.reload();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Konnte nicht geändert werden.");
    }
  }

  return (
    <div className="flex max-w-xl flex-col gap-3">
      {!d.available ? (
        <p role="note" className="m-0 border-l-4 border-line bg-sunk px-3 py-2 text-sm text-fg2">
          Passkeys brauchen auf dem Server die Variable <code>PATCHWATCH_PUBLIC_URL</code> (die Adresse, unter der du patchwatch öffnest).
        </p>
      ) : !webauthnSupported() ? (
        <p role="note" className="m-0 border-l-4 border-line bg-sunk px-3 py-2 text-sm text-fg2">Dieser Browser unterstützt keine Passkeys (oder die Seite läuft nicht über HTTPS).</p>
      ) : null}
      {d.passkeys.length > 0 ? (
        <ul className="m-0 flex list-none flex-col divide-y divide-line rounded-xs border border-line p-0">
          {d.passkeys.map((p) => (
            <li key={p.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2">
              <span className="min-w-0 flex-1">
                <span className="block font-semibold [overflow-wrap:anywhere]">{p.name}</span>
                <span className="block text-xs text-fg3">
                  Angelegt <RelTime iso={p.created_at} /> · zuletzt benutzt {p.last_used_at ? <RelTime iso={p.last_used_at} /> : "nie"}
                </span>
              </span>
              <Button variant="danger" onClick={() => void remove(p.id)} aria-label={`Passkey ${p.name} löschen`}>
                Löschen
              </Button>
            </li>
          ))}
        </ul>
      ) : (
        <p className="m-0 text-sm text-fg2">Noch kein Passkey. Mit einem Passkey meldest du dich per Fingerabdruck, Gesichtserkennung, PIN oder Sicherheitsschlüssel an.</p>
      )}
      <form onSubmit={(e) => void add(e)} className="flex flex-wrap items-end gap-3">
        <Field label="Name des Geräts (z. B. Laptop)">
          <TextInput value={name} onChange={(e) => setName(e.target.value)} maxLength={60} placeholder="Dieses Gerät" />
        </Field>
        <Button type="submit" variant="primary" busy={busy} disabled={!d.available || !webauthnSupported()}>
          Passkey hinzufügen
        </Button>
      </form>
      <Switch
        label="Anmeldung per Passwort für mein Konto ausschalten"
        hint={d.passkeys.length === 0 ? "Erst möglich, wenn ein Passkey angelegt ist. Das Passwortfeld bleibt sichtbar, wird aber für dein Konto abgelehnt." : "Danach geht die Anmeldung für dich nur noch mit Passkey. Löschst du den letzten Passkey, ist das Passwort wieder aktiv."}
        checked={d.password_login_disabled}
        disabled={d.passkeys.length === 0}
        onChange={(e) => void togglePassword(e.target.checked)}
      />
      {error ? <ErrorNote message={error} /> : null}
    </div>
  );
}
