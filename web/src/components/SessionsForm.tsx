"use client";

import { useState } from "react";
import { api, ApiError } from "@/lib/api";
import { useApi } from "@/lib/useApi";
import { toast } from "@/lib/toastStore";
import { Button } from "@/components/Controls";
import { ErrorNote, Loading } from "@/components/States";
import { RelTime } from "@/components/RelTime";

interface Sess {
  id: string;
  ip: string | null;
  user_agent: string | null;
  method: string;
  created_at: string;
  last_seen_at: string | null;
  expires_at: string;
  current: boolean;
}

const METHODS: Record<string, string> = { password: "Passwort", passkey: "Passkey", oidc: "SSO", ldap: "LDAP", totp: "Code", recovery: "Wiederherstellungscode" };

/** „password+totp“ → „Passwort + Code“. */
function methodLabel(m: string): string {
  return m.split("+").map((x) => METHODS[x] ?? x).join(" + ");
}

/** Grobe Beschreibung des Geräts aus dem User-Agent (Browser auf Betriebssystem). */
function device(ua: string | null): string {
  if (!ua) return "Unbekanntes Gerät";
  const browser = /Edg\//.test(ua) ? "Edge" : /OPR\//.test(ua) ? "Opera" : /Firefox\//.test(ua) ? "Firefox" : /Chrome\//.test(ua) ? "Chrome" : /Safari\//.test(ua) ? "Safari" : "Browser";
  const os = /Android/.test(ua) ? "Android" : /iPhone|iPad/.test(ua) ? "iOS" : /Windows/.test(ua) ? "Windows" : /Mac OS/.test(ua) ? "macOS" : /Linux/.test(ua) ? "Linux" : "";
  return os ? `${browser} auf ${os}` : browser;
}

/** Konto: eigene aktive Anmeldungen sehen und beenden (einzeln, alle anderen, überall). */
export function SessionsForm() {
  const q = useApi<{ sessions: Sess[] }>("/auth/sessions");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (!q.data) return q.error ? <ErrorNote message={q.error} /> : <Loading what="Anmeldungen" />;
  const list = q.data.sessions;

  async function run(fn: () => Promise<unknown>, ok: string, leave = false) {
    setBusy(true);
    setError(null);
    try {
      await fn();
      if (leave) {
        // Vollständiges Neuladen leert alle Zwischenspeicher der angemeldeten Sitzung.
        // eslint-disable-next-line @next/next/no-location-assign-relative-destination
        window.location.assign("/login");
        return;
      }
      toast.success(ok);
      await q.reload();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Das hat nicht geklappt.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex max-w-xl flex-col gap-3">
      <ul className="m-0 flex list-none flex-col divide-y divide-line rounded-xs border border-line p-0">
        {list.map((s) => (
          <li key={s.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2">
            <span className="min-w-0 flex-1">
              <span className="block font-semibold [overflow-wrap:anywhere]">
                {device(s.user_agent)}
                {s.current ? <span className="ml-2 rounded-full bg-accent-soft px-2 py-0.5 text-xs font-semibold text-accent">Dieses Gerät</span> : null}
              </span>
              <span className="block text-xs text-fg3 [overflow-wrap:anywhere]">
                {methodLabel(s.method)} · {s.ip ?? "IP unbekannt"} · angemeldet <RelTime iso={s.created_at} />
                {s.last_seen_at ? <> · zuletzt aktiv <RelTime iso={s.last_seen_at} /></> : null}
              </span>
            </span>
            {!s.current ? (
              <Button variant="danger" disabled={busy} aria-label={`${device(s.user_agent)} abmelden`} onClick={() => void run(() => api.del(`/auth/sessions/${s.id}`, { silent: true }), "Gerät abgemeldet.")}>
                Abmelden
              </Button>
            ) : null}
          </li>
        ))}
      </ul>
      <div className="flex flex-wrap gap-2">
        <Button disabled={busy || list.length < 2} onClick={() => void run(() => api.post("/auth/sessions/revoke-all", {}, { silent: true }), "Alle anderen Geräte abgemeldet.")}>
          Alle anderen abmelden
        </Button>
        <Button variant="danger" disabled={busy} onClick={() => void run(() => api.post("/auth/sessions/revoke-all", { include_current: true }, { silent: true }), "", true)}>
          Überall abmelden
        </Button>
      </div>
      {error ? <ErrorNote message={error} /> : null}
    </div>
  );
}
