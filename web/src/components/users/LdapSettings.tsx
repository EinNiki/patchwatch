"use client";

import { useState } from "react";
import { api, ApiError } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { toast } from "@/lib/toastStore";
import { Button, Field, Select, Switch, TextInput } from "@/components/Controls";
import { ErrorNote, Loading } from "@/components/States";
import type { LdapSettings as Settings } from "@/lib/types";

/** LDAP-Anmeldung mit festem Muster für den Bind-DN. Verbindung immer verschlüsselt (LDAPS oder StartTLS). */
export function LdapSettings() {
  const q = useApi<Settings>("/settings/ldap");
  if (!q.data) return q.error ? <ErrorNote message={q.error} /> : <Loading what="LDAP-Einstellungen" />;
  return <Form key={JSON.stringify(q.data)} s={q.data} reload={() => void q.reload()} />;
}

function Form({ s, reload }: { s: Settings; reload: () => void }) {
  const [f, setF] = useState(s);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [test, setTest] = useState<{ ok: boolean; message: string } | null>(null);
  const dirty = JSON.stringify(f) !== JSON.stringify(s);
  const set = <K extends keyof Settings>(k: K, v: Settings[K]) => setF((o) => ({ ...o, [k]: v }));

  async function save(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setTest(null);
    try {
      await api.put("/settings/ldap", f, { silent: true });
      toast.success("LDAP-Einstellungen gespeichert.");
      reload();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Speichern fehlgeschlagen.");
    } finally {
      setBusy(false);
    }
  }

  async function runTest() {
    setTest(null);
    try {
      const r = await api.post<{ ok: boolean; url?: string; message?: string }>("/settings/ldap/test", {}, { silent: true });
      setTest({ ok: r.ok, message: r.ok ? `Verbindung und Zertifikat in Ordnung (${r.url}).` : (r.message ?? "Verbindung fehlgeschlagen.") });
    } catch (err) {
      setTest({ ok: false, message: err instanceof ApiError ? err.message : "Test fehlgeschlagen." });
    }
  }

  return (
    <form onSubmit={(e) => void save(e)} className="flex max-w-xl flex-col gap-3">
      <Switch label="LDAP-Anmeldung aktiv" hint="Wer sich mit Benutzername und Passwort anmeldet und kein lokales Konto hat, wird gegen LDAP geprüft." checked={f.enabled} onChange={(e) => set("enabled", e.target.checked)} />
      <Field label="Verbindung">
        <Select value={f.security} onChange={(e) => set("security", e.target.value as Settings["security"])}>
          <option value="ldaps">LDAPS (verschlüsselt von Anfang an, Port 636)</option>
          <option value="starttls">StartTLS (Port 389, danach verschlüsselt)</option>
        </Select>
      </Field>
      <Field label="Server (Host oder Host:Port)">
        <TextInput value={f.server} onChange={(e) => set("server", e.target.value)} placeholder="ldap.firma.de" maxLength={253} autoComplete="off" />
      </Field>
      <Field label="Bind-Muster (feste DN mit {username})">
        <TextInput value={f.bind_pattern} onChange={(e) => set("bind_pattern", e.target.value)} placeholder="uid={username},ou=people,dc=firma,dc=de" maxLength={300} autoComplete="off" spellCheck={false} />
      </Field>
      <Field label="Anzeigename des Anbieters (optional)">
        <TextInput value={f.name} onChange={(e) => set("name", e.target.value)} maxLength={40} placeholder="Firmenverzeichnis" />
      </Field>
      <Field label="Neue Konten">
        <Select value={f.new_account} onChange={(e) => set("new_account", e.target.value as Settings["new_account"])}>
          <option value="pending">Warten auf Freigabe (ohne Rechte)</option>
          <option value="viewer">Sofort als „Nur Lesen“</option>
          <option value="reject">Nicht anlegen</option>
        </Select>
      </Field>
      <p className="m-0 text-xs text-fg3">Das Zertifikat des Servers wird immer geprüft; ohne TLS verbindet sich patchwatch nicht. Der Benutzername wird maskiert in das Muster eingesetzt, leere Passwörter werden nie gesendet.</p>
      {error ? <ErrorNote message={error} /> : null}
      {test ? (
        <p role="status" className={`m-0 border-l-4 px-3 py-2 text-sm ${test.ok ? "border-ok bg-ok-soft text-ok" : "border-crit bg-crit-soft text-crit"}`}>
          {test.message}
        </p>
      ) : null}
      <div className="flex flex-wrap gap-2">
        <Button type="submit" variant="primary" busy={busy} disabled={!dirty}>
          Speichern
        </Button>
        <Button onClick={() => void runTest()} disabled={dirty || !s.server} title={dirty ? "Erst speichern, dann testen." : undefined}>
          Verbindung testen
        </Button>
      </div>
    </form>
  );
}
