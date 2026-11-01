"use client";

import { useEffect, useState, useSyncExternalStore } from "react";
import { useRouter } from "next/navigation";
import { api, ApiError, setCsrf } from "@/lib/api";
import type { Me } from "@/lib/types";
import { Button, Field, TextInput } from "@/components/Controls";

// true erst nach der Hydration: vorher darf nichts abgeschickt werden.
const subscribe = () => () => {};

export default function LoginPage() {
  const router = useRouter();
  const hydrated = useSyncExternalStore(subscribe, () => true, () => false);
  const [formError, setError] = useState<string | null>(null);
  // Rückkehr von einer abgelehnten SSO-Anmeldung (?error=oidc).
  const ssoDenied = useSyncExternalStore(subscribe, () => window.location.search.includes("error=oidc"), () => false);
  const error = formError ?? (ssoDenied ? "Anmeldung per Single Sign-On abgelehnt. Ist dein Konto freigegeben?" : null);
  const [busy, setBusy] = useState(false);
  const [oidc, setOidc] = useState<{ enabled: boolean; name: string } | null>(null);

  useEffect(() => {
    api.get<{ oidc: { enabled: boolean; name: string } }>("/auth/providers").then((p) => setOidc(p.oidc), () => undefined);
  }, []);

  async function submit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    setBusy(true);
    setError(null);
    try {
      const me = await api.post<Me>("/auth/login", {
        username: String(form.get("username") ?? ""),
        password: String(form.get("password") ?? ""),
      });
      setCsrf(me.csrf_token);
      router.replace("/");
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) setError("Benutzername oder Passwort falsch.");
      else if (err instanceof ApiError && err.status === 429) setError("Zu viele Anmeldeversuche. Bitte in einigen Minuten erneut versuchen.");
      else setError("Server nicht erreichbar. Läuft die API?");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main id="main" tabIndex={-1} className="mx-auto flex min-h-dvh max-w-sm flex-col justify-center px-4">
      <h1 className="mb-1 font-mono text-xl font-medium">patchwatch</h1>
      <p className="mb-5 text-fg2">Anmeldung für Administratoren</p>
      {/* method="post": Selbst wenn JavaScript fehlt, landen Zugangsdaten nie in der URL. */}
      <form method="post" action="/login" onSubmit={(e) => void submit(e)} className="flex flex-col gap-3 border border-line bg-surface p-4">
        <Field label="Benutzername">
          <TextInput name="username" autoComplete="username" required maxLength={64} />
        </Field>
        <Field label="Passwort">
          <TextInput name="password" type="password" autoComplete="current-password" required maxLength={256} />
        </Field>
        {error ? (
          <p role="alert" className="border-l-4 border-crit bg-crit-soft px-3 py-2 text-crit">
            {error}
          </p>
        ) : null}
        <Button type="submit" variant="primary" busy={busy} disabled={!hydrated}>
          Anmelden
        </Button>
      </form>
      {oidc?.enabled ? (
        <a
          href="/api/v1/auth/oidc/login"
          className="mt-3 inline-flex min-h-9 items-center justify-center border border-control bg-surface px-3 font-semibold hover:border-accent max-md:min-h-11"
        >
          Mit {oidc.name} anmelden
        </a>
      ) : null}
    </main>
  );
}
