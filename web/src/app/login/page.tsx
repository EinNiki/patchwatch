"use client";

import { useEffect, useRef, useState, useSyncExternalStore } from "react";
import { useRouter } from "next/navigation";
import { api, ApiError, setCsrf } from "@/lib/api";
import type { Me } from "@/lib/types";
import { Button, Field, TextInput } from "@/components/Controls";
import { getPasskey, passkeyErrorText, webauthnSupported } from "@/lib/webauthn";

// true erst nach der Hydration: vorher darf nichts abgeschickt werden.
const subscribe = () => () => {};

/** Schwebende Chips: [Text, x in %, y in %, Tiefe]. Die Ruhelage liegt um die Karte herum, nie darunter. */
const FLOATERS: [string, number, number, number][] = [
  ["Ubuntu", 14, 22, 1],
  ["Debian", 80, 18, 0.8],
  ["CVE", 26, 70, 1.2],
  ["Proxmox", 86, 62, 0.9],
  ["Alpine", 8, 52, 0.7],
  ["Fedora", 72, 84, 1.1],
  ["NVD", 36, 10, 0.9],
  ["RHEL", 62, 8, 1.2],
  ["Arch", 92, 38, 0.7],
  ["openSUSE", 18, 90, 0.8],
  ["OSV", 50, 93, 1],
];

/**
 * Chips schweben frei (langsame Sinusbewegung) und folgen dem Mauszeiger sanft: jeder Chip wandert ein Stück in dessen
 * Richtung (je nach Tiefe unterschiedlich weit, mit Verzögerung), die Karte liegt darüber. Aus bei „weniger Bewegung“
 * und auf Touch-Fenstern; die Chips sind reine Dekoration (aria-hidden).
 */
function Floaters() {
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = box.current;
    if (!el || window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const chips = Array.from(el.children) as HTMLElement[];
    const pos = chips.map(() => ({ x: 0, y: 0 }));
    let mouse: { x: number; y: number } | null = null;
    const move = (e: PointerEvent) => {
      mouse = e.pointerType === "mouse" ? { x: e.clientX, y: e.clientY } : null;
    };
    const leave = () => {
      mouse = null;
    };
    window.addEventListener("pointermove", move);
    document.documentElement.addEventListener("pointerleave", leave);
    let raf = 0;
    const tick = (t: number) => {
      const r = el.getBoundingClientRect();
      const sec = t / 1000;
      chips.forEach((c, i) => {
        const [, fx, fy, depth] = FLOATERS[i]!;
        const bx = r.left + (fx / 100) * r.width;
        const by = r.top + (fy / 100) * r.height;
        // Schweben: zwei Sinuswellen mit eigener Phase je Chip.
        const dx = Math.sin(sec * 0.45 + i * 1.7) * 16 * depth;
        const dy = Math.cos(sec * 0.38 + i * 2.3) * 13 * depth;
        // Anziehung: ein Teil der Strecke zum Zeiger, begrenzt, damit nichts davonfliegt.
        let tx = 0;
        let ty = 0;
        if (mouse) {
          const vx = mouse.x - bx;
          const vy = mouse.y - by;
          const dist = Math.hypot(vx, vy) || 1;
          const pull = Math.min(dist * 0.22 * depth, 150);
          tx = (vx / dist) * pull;
          ty = (vy / dist) * pull;
        }
        const p = pos[i]!;
        p.x += (tx - p.x) * 0.045;
        p.y += (ty - p.y) * 0.045;
        c.style.transform = `translate3d(${(dx + p.x).toFixed(1)}px, ${(dy + p.y).toFixed(1)}px, 0)`;
      });
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("pointermove", move);
      document.documentElement.removeEventListener("pointerleave", leave);
    };
  }, []);
  return (
    <div ref={box} aria-hidden="true" className="pointer-events-none absolute inset-0 max-md:hidden">
      {FLOATERS.map(([label, x, y, depth]) => (
        <span
          key={label}
          className="absolute will-change-transform"
          style={{ left: `${x}%`, top: `${y}%`, marginLeft: "-2.5rem", opacity: 0.6 + depth * 0.3 }}
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
  const [passkey, setPasskey] = useState(false);

  useEffect(() => {
    api.get<{ oidc: { enabled: boolean; name: string }; passkey?: boolean }>("/auth/providers").then(
      (p) => {
        setOidc(p.oidc);
        setPasskey(Boolean(p.passkey));
      },
      () => undefined,
    );
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

  // Anmeldung mit Passkey: Name aus dem Feld, Gerät bestätigt (PIN, Fingerabdruck …); danach wie bei der Passwort-Anmeldung.
  async function passkeyLogin(form: HTMLFormElement | null) {
    const username = String(new FormData(form ?? undefined).get("username") ?? "").trim();
    if (!username) return setError("Gib zuerst deinen Benutzernamen ein, dann „Mit Passkey anmelden“.");
    setBusy(true);
    setError(null);
    try {
      const start = await api.post<{ ceremony: string; options: { publicKey: Record<string, unknown> } }>("/auth/passkey/login/start", { username }, { silent: true });
      const credential = await getPasskey(start.options);
      const me = await api.post<Me>("/auth/passkey/login/finish", { ceremony: start.ceremony, credential }, { silent: true });
      setCsrf(me.csrf_token);
      try {
        window.localStorage.removeItem("pw-nav:notifications");
      } catch {
        /* Speicher gesperrt: egal */
      }
      router.replace("/");
    } catch (err) {
      if (err instanceof ApiError && err.status === 429) setError("Zu viele Versuche. Bitte in einigen Minuten erneut versuchen.");
      else if (err instanceof ApiError && err.status === 401) setError("Passkey abgelehnt. Gibt es für diesen Benutzer einen Passkey?");
      else setError(passkeyErrorText(err));
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
      <Floaters />
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
          {passkey || oidc?.enabled ? (
            <>
              <div className="flex items-center gap-3 text-xs text-fg3" role="separator">
                <span className="h-px flex-1 bg-line" />
                oder
                <span className="h-px flex-1 bg-line" />
              </div>
              {passkey ? (
                <Button
                  disabled={!hydrated || !webauthnSupported()}
                  onClick={(e) => void passkeyLogin(e.currentTarget.form)}
                  title={webauthnSupported() ? undefined : "Dieser Browser unterstützt keine Passkeys (oder die Seite läuft nicht über HTTPS)."}
                  className="w-full"
                >
                  Mit Passkey anmelden
                </Button>
              ) : null}
              {oidc?.enabled ? (
              <a
                href="/api/v1/auth/oidc/login"
                className="inline-flex min-h-9 items-center justify-center rounded-sm border border-control bg-surface px-3 font-semibold no-underline hover:border-accent max-md:min-h-11"
              >
                Mit {oidc.name} anmelden
              </a>
              ) : null}
            </>
          ) : null}
        </form>
        <p className="mt-4 text-center text-xs text-fg3">Die Verbindung sollte über HTTPS laufen.
          <br />
          Mehrere Fehlversuche sperren die Anmeldung kurz.</p>
      </div>
    </main>
  );
}
