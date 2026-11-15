"use client";

import { useState } from "react";
import QRCode from "qrcode";
import { api, ApiError } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { toast } from "@/lib/toastStore";
import { Button, Field, TextInput } from "@/components/Controls";
import { ErrorNote, Loading } from "@/components/States";

interface Status {
  enabled: boolean;
  recovery_codes_left: number;
  secret_encrypted: boolean;
}

/** Konto: Zwei-Faktor-Anmeldung (TOTP) einrichten, Wiederherstellungscodes einmalig anzeigen, ausschalten. */
export function TwoFactorForm() {
  const q = useApi<Status>("/auth/2fa");
  const [setup, setSetup] = useState<{ secret: string; qr: string } | null>(null);
  const [codes, setCodes] = useState<string[] | null>(null);
  const [code, setCode] = useState("");
  const [password, setPassword] = useState("");
  const [off, setOff] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!q.data) return q.error ? <ErrorNote message={q.error} /> : <Loading what="Zwei-Faktor-Status" />;
  const d = q.data;

  async function start() {
    setBusy(true);
    setError(null);
    try {
      const r = await api.post<{ secret: string; otpauth_uri: string }>("/auth/2fa/setup", {}, { silent: true });
      setSetup({ secret: r.secret, qr: await QRCode.toDataURL(r.otpauth_uri, { margin: 1, width: 192 }) });
      setCode("");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Einrichtung fehlgeschlagen.");
    } finally {
      setBusy(false);
    }
  }

  async function enable(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const r = await api.post<{ recovery_codes: string[] }>("/auth/2fa/enable", { code: code.trim() }, { silent: true });
      setCodes(r.recovery_codes);
      setSetup(null);
      setCode("");
      await q.reload();
    } catch (err) {
      setError(err instanceof ApiError && err.status === 400 ? "Code stimmt nicht. Prüfe die Uhrzeit des Geräts und versuche es erneut." : err instanceof ApiError ? err.message : "Aktivieren fehlgeschlagen.");
    } finally {
      setBusy(false);
    }
  }

  async function disable(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.post("/auth/2fa/disable", { code: code.trim(), password }, { silent: true });
      toast.success("Zwei-Faktor-Anmeldung ausgeschaltet.");
      setOff(false);
      setCode("");
      setPassword("");
      await q.reload();
    } catch (err) {
      setError(err instanceof ApiError && err.status === 403 ? "Passwort oder Code falsch." : err instanceof ApiError ? err.message : "Ausschalten fehlgeschlagen.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex max-w-xl flex-col gap-3">
      {codes ? (
        <div role="note" className="flex flex-col gap-2 rounded-xs border border-line bg-sunk p-3">
          <p className="m-0 font-semibold">Wiederherstellungscodes – nur jetzt sichtbar</p>
          <p className="m-0 text-sm text-fg2">Bewahre sie sicher auf. Jeder Code funktioniert einmal, falls dein Authenticator fehlt.</p>
          <ul className="m-0 grid list-none grid-cols-1 gap-x-6 gap-y-1 p-0 font-mono text-sm min-[420px]:grid-cols-2">
            {codes.map((c) => (
              <li key={c}>{c}</li>
            ))}
          </ul>
          <div className="flex gap-2">
            <Button onClick={() => void navigator.clipboard?.writeText(codes.join("\n")).then(() => toast.success("Codes kopiert."))}>Kopieren</Button>
            <Button variant="primary" onClick={() => setCodes(null)}>Gespeichert, schließen</Button>
          </div>
        </div>
      ) : null}
      {d.enabled ? (
        <>
          <p className="m-0 text-sm text-fg2">
            Aktiv. Beim Anmelden mit Passwort wird zusätzlich ein Code abgefragt. Übrige Wiederherstellungscodes: <strong>{d.recovery_codes_left}</strong>. Passkey- und SSO-Anmeldung fragen keinen Code ab.
          </p>
          {off ? (
            <form onSubmit={(e) => void disable(e)} className="flex flex-wrap items-end gap-3">
              <Field label="Passwort">
                <TextInput type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
              </Field>
              <Field label="Code oder Wiederherstellungscode">
                <TextInput autoComplete="one-time-code" required value={code} onChange={(e) => setCode(e.target.value)} maxLength={16} />
              </Field>
              <Button type="submit" variant="danger" busy={busy}>Ausschalten</Button>
              <Button onClick={() => { setOff(false); setError(null); }}>Abbrechen</Button>
            </form>
          ) : (
            <Button variant="danger" className="self-start" onClick={() => setOff(true)}>Zwei-Faktor ausschalten</Button>
          )}
        </>
      ) : setup ? (
        <form onSubmit={(e) => void enable(e)} className="flex flex-col gap-3">
          <p className="m-0 text-sm text-fg2">Scanne den QR-Code mit deiner Authenticator-App oder gib den Schlüssel von Hand ein. Bestätige dann mit dem angezeigten Code.</p>
          <div className="flex flex-wrap items-center gap-4">
            {/* eslint-disable-next-line @next/next/no-img-element -- Data-URL, kein Bild zum Optimieren */}
            <img src={setup.qr} width={192} height={192} alt="QR-Code zum Einrichten der Authenticator-App" className="rounded-xs border border-line bg-white" />
            <p className="m-0 text-sm [overflow-wrap:anywhere]">
              <span className="block text-fg3">Schlüssel</span>
              <code className="font-mono">{setup.secret}</code>
            </p>
          </div>
          <div className="flex flex-wrap items-end gap-3">
            <Field label="6-stelliger Code">
              <TextInput inputMode="numeric" autoComplete="one-time-code" required maxLength={6} pattern="[0-9]{6}" value={code} onChange={(e) => setCode(e.target.value)} className="w-32 font-mono" />
            </Field>
            <Button type="submit" variant="primary" busy={busy}>Aktivieren</Button>
            <Button onClick={() => { setSetup(null); setError(null); }}>Abbrechen</Button>
          </div>
        </form>
      ) : (
        <>
          <p className="m-0 text-sm text-fg2">Schützt dein Konto zusätzlich zum Passwort mit einem Code aus einer Authenticator-App (TOTP).</p>
          {!d.secret_encrypted ? (
            <p role="note" className="m-0 border-l-4 border-line bg-sunk px-3 py-2 text-sm text-fg2">
              Ohne <code>PATCHWATCH_SECRET_KEY</code> speichert der Server das Geheimnis unverschlüsselt in der Datenbank.
            </p>
          ) : null}
          <Button variant="primary" className="self-start" busy={busy} onClick={() => void start()}>Zwei-Faktor einrichten</Button>
        </>
      )}
      {error ? <ErrorNote message={error} /> : null}
    </div>
  );
}
