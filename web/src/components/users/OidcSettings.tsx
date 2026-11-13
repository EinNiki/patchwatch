"use client";

import { useState } from "react";
import { api, ApiError } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { toast } from "@/lib/toastStore";
import { Button, Checkbox, Field, Select, TextInput } from "@/components/Controls";
import { CodeField } from "@/components/CopyButton";
import { Icon, NavIcon } from "@/components/Icons";
import { ErrorNote, Loading } from "@/components/States";
import { useAuth } from "@/components/AuthProvider";
import type { OidcSettings as Settings } from "@/lib/types";
import type { RolesResponse } from "@/lib/roles";

interface TestResult {
  ok: boolean;
  keys?: number;
  message?: string;
}

export function OidcSettings({ roles }: { roles: RolesResponse | undefined }) {
  const q = useApi<Settings>("/settings/oidc");
  if (!q.data) return q.error ? <ErrorNote message={q.error} /> : <Loading what="OIDC-Einstellungen" />;
  // `key` setzt das Formular nach dem Speichern auf den gespeicherten Stand zurück.
  return <Form key={JSON.stringify([q.data.issuer, q.data.client_id, q.data.group_roles, q.data.new_account, q.data.enabled])} s={q.data} roles={roles} reload={() => void q.reload()} />;
}

function Form({ s, roles, reload }: { s: Settings; roles: RolesResponse | undefined; reload: () => void }) {
  const { me } = useAuth();
  const [f, setF] = useState({
    enabled: s.enabled,
    name: s.name,
    issuer: s.issuer,
    client_id: s.client_id,
    client_secret: "",
    redirect_url: s.redirect_url,
    scopes: s.scopes,
    group_claim: s.group_claim,
    new_account: s.new_account,
    domains: s.allowed_domains.join(", "),
    emails: s.allowed_emails.join(", "),
  });
  const [groups, setGroups] = useState(s.group_roles);
  const [pw, setPw] = useState("");
  const [busy, setBusy] = useState(false);
  const [testing, setTesting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [test, setTest] = useState<TestResult | null>(null);
  const set = <K extends keyof typeof f>(k: K, v: (typeof f)[K]) => setF((x) => ({ ...x, [k]: v }));
  const list = (v: string) => v.split(/[,\s]+/).map((x) => x.trim()).filter(Boolean);
  const hasAdminMap = groups.some((g) => g.role === "admin");

  async function save(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await api.put("/settings/oidc", {
        enabled: f.enabled,
        issuer: f.issuer,
        client_id: f.client_id,
        client_secret: f.client_secret || undefined,
        redirect_url: s.public_url_set ? undefined : f.redirect_url,
        name: f.name,
        scopes: f.scopes,
        allowed_domains: list(f.domains),
        allowed_emails: list(f.emails),
        group_claim: f.group_claim,
        group_roles: groups.filter((g) => g.group.trim()),
        new_account: f.new_account,
        current_password: hasAdminMap && me.auth_kind !== "oidc" ? pw : undefined,
      }, { silent: true });
      setPw("");
      toast.success("OIDC-Einstellungen gespeichert.");
      reload();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Speichern fehlgeschlagen.");
    } finally {
      setBusy(false);
    }
  }

  async function runTest() {
    setTesting(true);
    setTest(null);
    try {
      setTest(await api.post<TestResult>("/settings/oidc/test", undefined, { silent: true }));
    } catch (err) {
      setTest({ ok: false, message: err instanceof ApiError ? err.message : "Test fehlgeschlagen." });
    } finally {
      setTesting(false);
    }
  }

  return (
    <form onSubmit={(e) => void save(e)} className="flex max-w-2xl flex-col gap-3">
      {s.source === "env" ? (
        <p className="m-0 border-l-4 border-warn bg-warn-soft px-3 py-2 text-warn">
          Die Werte stammen aus Umgebungsvariablen. Speichern legt eine Einstellung in der Datenbank an, die ab dann Vorrang hat.
        </p>
      ) : null}
      {!s.secret_storage ? (
        <p className="m-0 border-l-4 border-warn bg-warn-soft px-3 py-2 text-warn">
          PATCHWATCH_SECRET_KEY ist nicht gesetzt: das Client-Secret lässt sich nicht speichern.
        </p>
      ) : null}
      <Checkbox label="Anmeldung per OIDC aktivieren" checked={f.enabled} onChange={(e) => set("enabled", e.target.checked)} />
      <Field label="Name auf dem Anmelde-Knopf (z. B. Authentik)">
        <TextInput value={f.name} onChange={(e) => set("name", e.target.value)} maxLength={40} />
      </Field>
      <Field label="Issuer (https://…)">
        <TextInput value={f.issuer} onChange={(e) => set("issuer", e.target.value)} autoComplete="off" placeholder="https://auth.example.org/application/o/patchwatch" />
      </Field>
      <Field label="Client-ID">
        <TextInput value={f.client_id} onChange={(e) => set("client_id", e.target.value)} autoComplete="off" />
      </Field>
      <Field label={s.secret_set ? "Client-Secret (gesetzt, leer lassen zum Behalten)" : "Client-Secret"}>
        <TextInput type="password" value={f.client_secret} onChange={(e) => set("client_secret", e.target.value)} autoComplete="new-password" />
      </Field>
      {s.public_url_set ? (
        <div>
          <p className="mb-1 text-xs font-semibold text-fg2">Redirect-URI (beim Anbieter eintragen)</p>
          <CodeField text={s.redirect_url} label="Redirect-URI kopieren" />
        </div>
      ) : (
        <Field label="Redirect-URI (PATCHWATCH_PUBLIC_URL ist nicht gesetzt)">
          <TextInput value={f.redirect_url} onChange={(e) => set("redirect_url", e.target.value)} placeholder="https://patchwatch.example.org/api/v1/auth/oidc/callback" />
        </Field>
      )}
      <Field label="Scopes (leer = openid email profile)">
        <TextInput value={f.scopes} onChange={(e) => set("scopes", e.target.value)} autoComplete="off" />
      </Field>

      <fieldset className="m-0 flex flex-col gap-2 border-0 p-0">
        <legend className="mb-1 text-sm font-semibold">Neue Konten und Gruppen</legend>
        <Field label="Neue Konten">
          <Select value={f.new_account} onChange={(e) => set("new_account", e.target.value as Settings["new_account"])}>
            <option value="pending">Warten auf Freigabe (Standard)</option>
            <option value="viewer">Nur Lesen vergeben (bei Gruppenzuordnung oder erlaubter Domäne)</option>
            <option value="reject">Ablehnen</option>
          </Select>
        </Field>
        <Field label="Gruppen-Claim">
          <TextInput value={f.group_claim} onChange={(e) => set("group_claim", e.target.value)} placeholder="groups" />
        </Field>
        <div>
          <p className="mb-1 text-xs font-semibold text-fg2">Gruppe → Rolle (ist eine Zuordnung eingerichtet, gilt sie als maßgeblich)</p>
          {groups.map((g, i) => (
            <div key={i} className="mb-1 flex flex-wrap items-center gap-2">
              <TextInput aria-label={`Gruppe ${i + 1}`} value={g.group} onChange={(e) => setGroups(groups.map((x, j) => (j === i ? { ...x, group: e.target.value } : x)))} placeholder="Gruppenname" className="min-w-0 flex-1" />
              <Select aria-label={`Rolle für Gruppe ${i + 1}`} value={g.role} onChange={(e) => setGroups(groups.map((x, j) => (j === i ? { ...x, role: e.target.value } : x)))}>
                {(roles?.roles ?? [{ key: "viewer", title: "Nur Lesen", permissions: [] }]).map((r) => (
                  <option key={r.key} value={r.key}>
                    {r.title}
                  </option>
                ))}
              </Select>
              <Button size="icon" aria-label={`Zuordnung ${i + 1} entfernen`} title="Entfernen" onClick={() => setGroups(groups.filter((_, j) => j !== i))}>
                <NavIcon name="close" />
              </Button>
            </div>
          ))}
          <Button onClick={() => setGroups([...groups, { group: "", role: "viewer" }])}>
            <NavIcon name="plus" />
            Zuordnung hinzufügen
          </Button>
          <p className="mb-0 mt-1 text-xs text-fg3">Eine Hochstufung durch den Anbieter wirkt erst nach Bestätigung eines Administrators, eine Herabstufung sofort.</p>
        </div>
        {hasAdminMap && me.auth_kind !== "oidc" ? (
          <Field label="Dein Passwort (nötig für neue Administrator-Zuordnungen)">
            <TextInput type="password" value={pw} onChange={(e) => setPw(e.target.value)} autoComplete="current-password" />
          </Field>
        ) : null}
        <Field label="Erlaubte Domänen (nur für „Nur Lesen vergeben“, verifizierte E-Mail nötig)">
          <TextInput value={f.domains} onChange={(e) => set("domains", e.target.value)} placeholder="example.org" />
        </Field>
        <Field label="Erlaubte E-Mail-Adressen (wie oben)">
          <TextInput value={f.emails} onChange={(e) => set("emails", e.target.value)} />
        </Field>
      </fieldset>

      {error ? <ErrorNote message={error} /> : null}
      {test ? (
        <p role="status" className={`m-0 flex items-center gap-2 ${test.ok ? "text-ok" : "text-crit"}`}>
          <Icon name={test.ok ? "ok" : "crit"} />
          {test.ok ? `Verbindung in Ordnung, ${test.keys} Signaturschlüssel gefunden.` : `Verbindung fehlgeschlagen: ${test.message}`}
        </p>
      ) : null}
      <div className="flex flex-wrap justify-end gap-2">
        <Button onClick={() => void runTest()} busy={testing}>
          Verbindung testen
        </Button>
        <Button type="submit" variant="primary" busy={busy}>
          Speichern
        </Button>
      </div>
      <p className="m-0 text-xs text-fg3">Der Verbindungstest prüft die gespeicherten Werte; speichere zuerst.</p>
    </form>
  );
}
