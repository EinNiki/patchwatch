"use client";

import { useEffect, useState, useSyncExternalStore } from "react";
import { useRouter } from "next/navigation";
import { api, ApiError, setCsrf } from "@/lib/api";
import type { Me } from "@/lib/types";
import { Button, Field, TextInput } from "@/components/Controls";

// true erst nach der Hydration: vorher darf nichts abgeschickt werden.
const subscribe = () => () => {};

/** Chips auf den beiden Ringen: [Text, Winkel in Grad]. Innerer Ring läuft rechtsherum, äußerer linksherum. */
const INNER: [string, number][] = [["Ubuntu", 0], ["Debian", 72], ["CVE", 144], ["Proxmox", 216], ["Alpine", 288]];
const OUTER: [string, number][] = [["Fedora", 20], ["NVD", 80], ["RHEL", 140], ["Arch", 200], ["openSUSE", 260], ["OSV", 320]];

function Orbit({ radius, dur, items, reverse }: { radius: number; dur: number; items: [string, number][]; reverse?: boolean }) {
  return (
    <div aria-hidden="true" style={{ "--r": `${radius}px` } as React.CSSProperties}>
      <span className="orbit-ring" />
      {items.map(([label, a]) => (
        <span
          key={label}
          className="orbit-item"
          style={{ "--a": `${a}deg`, "--r": `${radius}px`, "--dur": `${dur}s`, animationDirection: reverse ? "reverse" : "normal" } as React.CSSProperties}
        >
          <span className="inline-flex items-center gap-1.5 rounded-full border border-line bg-surface px-3 py-1 text-xs font-semibold text-fg2 shadow-(--shadow-float)">
            <span className="size-1.5 rounded-full bg-accent" />
            {label}
          </span>
        </span>
      ))}
    </div>
  );
}

export default function LoginPage() {
  const router = useRouter();
  const hydrated = useSyncExternalStore(subscribe, () => true, () => false);
  const [formError, setError] = useState<string | null>(null);
  // Rückkehr von einer abgelehnten SSO-Anmeldung (?error=oidc).
  const ssoDenied = useSyncExternalStore(subscribe, () => window.location.search.includes("error=oidc"), () => false);
  const error = formError ?? (ssoDenied ? "Anmeldung per Single Sign-On abgelehnt. Ist dein Konto freigegeben?" : null);
  const [busy, setBusy] = useState(false);
  const [show, setShow] = useState(false);
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
      // Nach der Anmeldung startet die Seitenleiste immer mit eingeklappten Benachrichtigungen.
      try {
        window.localStorage.removeItem("pw-nav:notifications");
      } catch {
        /* Speicher gesperrt: egal */
      }
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
    <main
      id="main"
      tabIndex={-1}
      // Hintergrund: weicher Farbverlauf aus dem Akzent plus feines Punktraster; beides aus den Design-Token, also hell und dunkel passend.
      className="relative flex min-h-dvh flex-col items-center justify-center overflow-hidden px-4 py-10"
      style={{
        backgroundImage:
          "radial-gradient(60rem 36rem at 15% -10%, color-mix(in srgb, var(--accent) 18%, transparent), transparent 70%), radial-gradient(48rem 30rem at 100% 110%, color-mix(in srgb, var(--accent) 14%, transparent), transparent 70%), radial-gradient(color-mix(in srgb, var(--text-3) 30%, transparent) 1px, transparent 1px)",
        backgroundSize: "auto, auto, 22px 22px",
      }}
    >
      <Orbit radius={300} dur={70} items={INNER} />
      <Orbit radius={440} dur={110} items={OUTER} reverse />
      <div className="relative w-full max-w-sm">
        <div className="mb-6 flex flex-col items-center text-center">
          <svg width="44" height="44" viewBox="0 0 32 32" aria-hidden="true" focusable="false" className="mb-3 rounded-lg shadow-(--shadow-float)">
            <rect width="32" height="32" rx="6" fill="var(--accent)" />
            <path d="M9 16.5l4.5 4.5L23 11" fill="none" stroke="var(--bg)" strokeWidth="3.2" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          <h1 className="m-0 font-mono text-xl font-medium">patchwatch</h1>
        </div>
        {/* method="post": Selbst wenn JavaScript fehlt, landen Zugangsdaten nie in der URL. */}
        <form
          method="post"
          action="/login"
          onSubmit={(e) => void submit(e)}
          className="flex flex-col gap-4 rounded-lg border border-line bg-surface p-6 shadow-(--shadow-float)"
        >
          <Field label="Benutzername">
            <TextInput name="username" autoComplete="username" autoCapitalize="none" spellCheck={false} required maxLength={64} />
          </Field>
          {/* Der Umschalter liegt außerhalb des <label>, damit der Name des Feldes „Passwort“ bleibt. */}
          <div className="relative">
            <Field label="Passwort">
              <TextInput name="password" type={show ? "text" : "password"} autoComplete="current-password" required maxLength={256} className="w-full pr-12" />
            </Field>
            <Button
              variant="ghost"
              data-hit="none"
              aria-pressed={show}
              aria-label={show ? "Eingabe verbergen" : "Eingabe anzeigen"}
              onClick={() => setShow(!show)}
              className="absolute bottom-0.5 right-0.5 h-7! min-h-0! w-9! min-w-0! border-0! px-0! text-fg3 hover:text-fg max-md:bottom-0 max-md:h-11! max-md:w-11!"
            >
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false">
                <path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z" />
                <circle cx="12" cy="12" r="3" />
                {show ? <path d="M4 4l16 16" /> : null}
              </svg>
            </Button>
          </div>
          {error ? (
            <p role="alert" className="m-0 rounded-sm border-l-4 border-crit bg-crit-soft px-3 py-2 text-crit">
              {error}
            </p>
          ) : null}
          <Button type="submit" variant="primary" busy={busy} disabled={!hydrated} className="w-full">
            Anmelden
          </Button>
          {oidc?.enabled ? (
            <>
              <div className="flex items-center gap-3 text-xs text-fg3" role="separator">
                <span className="h-px flex-1 bg-line" />
                oder
                <span className="h-px flex-1 bg-line" />
              </div>
              <a
                href="/api/v1/auth/oidc/login"
                className="inline-flex min-h-9 items-center justify-center rounded-sm border border-control bg-surface px-3 font-semibold no-underline hover:border-accent max-md:min-h-11"
              >
                Mit {oidc.name} anmelden
              </a>
            </>
          ) : null}
        </form>
        <p className="mt-4 text-center text-xs text-fg3">Die Verbindung sollte über HTTPS laufen. Mehrere Fehlversuche sperren die Anmeldung kurz.</p>
      </div>
    </main>
  );
}
