"use client";

import { useEffect, useRef, useState, useSyncExternalStore } from "react";
import { useRouter } from "next/navigation";
import { api, ApiError, setCsrf } from "@/lib/api";
import type { Me } from "@/lib/types";
import { Button, TextInput } from "@/components/Controls";
import { DISTRO_ICONS } from "@/lib/distroIcons";
import { getPasskey, passkeyErrorText, webauthnSupported } from "@/lib/webauthn";

// true erst nach der Hydration: vorher darf nichts abgeschickt werden.
const subscribe = () => () => {};

/** Bahnen: Größe relativ zum Fenster (k), Umlaufzeit in s (negativ = gegen den Uhrzeigersinn) und die Logos darauf. */
const RINGS: { k: number; period: number; icons: string[] }[] = [
  { k: 0.4, period: 70, icons: ["Ubuntu", "Debian", "Fedora"] },
  { k: 0.47, period: -90, icons: ["Alpine", "Arch", "Proxmox"] },
  { k: 0.54, period: 120, icons: ["RHEL", "openSUSE"] },
];

/**
 * Logos kreisen (ohne sichtbare Linien) in Abstand um die Anmeldekarte. Die Mitte folgt dem Mauszeiger ein paar Pixel (sanft
 * nachgezogen). Aus bei „weniger Bewegung“ (Logos stehen dann still) und auf kleinen Fenstern; reine Dekoration.
 */
function Orbits() {
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = box.current;
    if (!el) return;
    const icons = Array.from(el.querySelectorAll<HTMLElement>("[data-orbit]"));
    const still = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    let target = { x: 0, y: 0 };
    const cur = { x: 0, y: 0 };
    const move = (e: PointerEvent) => {
      if (e.pointerType !== "mouse") return;
      const r = el.getBoundingClientRect();
      target = { x: ((e.clientX - r.left) / r.width - 0.5) * 36, y: ((e.clientY - r.top) / r.height - 0.5) * 36 };
    };
    if (!still) window.addEventListener("pointermove", move);
    let raf = 0;
    const size = { w: 0, h: 0 };
    const tick = (t: number) => {
      size.w = el.clientWidth;
      size.h = el.clientHeight;
      cur.x += (target.x - cur.x) * 0.05;
      cur.y += (target.y - cur.y) * 0.05;
      el.style.setProperty("--ox", `${cur.x.toFixed(1)}px`);
      el.style.setProperty("--oy", `${cur.y.toFixed(1)}px`);
      icons.forEach((c) => {
        const ri = Number(c.dataset.ring);
        const ring = RINGS[ri]!;
        const n = ring.icons.length;
        const a = (Number(c.dataset.i) / n) * Math.PI * 2 + (still ? 0 : ((t / 1000) / ring.period) * Math.PI * 2) + Number(c.dataset.ring);
        // Ellipse passend zum Fenster: rx/ry wachsen mit Breite/Höhe, nie enger als die Karte (Handy: Logos laufen dahinter).
        let rx = Math.max(size.w * ring.k, 250 + ri * 60);
        let ry = size.h * ring.k;
        // Schmale Fenster (Handy): Logos bleiben komplett im Bild, statt seitlich hinauszufliegen.
        if (size.w < 768) {
          rx = Math.min(rx, size.w / 2 - 26);
          ry = Math.min(ry, size.h / 2 - 26);
        }
        c.style.transform = `translate3d(${(Math.cos(a) * rx).toFixed(1)}px, ${(Math.sin(a) * ry).toFixed(1)}px, 0)`;
      });
      if (!still) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("pointermove", move);
    };
  }, []);
  return (
    <div ref={box} aria-hidden="true" className="pointer-events-none absolute inset-0 overflow-hidden">
      <div className="absolute left-1/2 top-1/2" style={{ transform: "translate(var(--ox, 0px), var(--oy, 0px))" }}>
        {RINGS.map((ring, ri) => (
          <div key={ring.k}>
            {ring.icons.map((name, i) => (
              <span key={name} data-orbit data-ring={ri} data-i={i} className="absolute will-change-transform" style={{ left: -20, top: -20 }}>
                <span className="flex size-10 items-center justify-center rounded-full border border-line bg-surface shadow-(--shadow-float)">
                  <svg viewBox="0 0 24 24" className="size-5" fill={DISTRO_ICONS[name]!.hex}>
                    <path d={DISTRO_ICONS[name]!.path} />
                  </svg>
                </span>
              </span>
            ))}
          </div>
        ))}
      </div>
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
  // Ohne Namen: das Gerät zeigt seine Passkeys für diese Seite zur Auswahl.
  async function passkeyLogin() {
    setBusy(true);
    setError(null);
    try {
      const start = await api.post<{ ceremony: string; options: { publicKey: Record<string, unknown> } }>("/auth/passkey/login/start", {}, { silent: true });
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
      else if (err instanceof ApiError && err.status === 401) setError("Passkey abgelehnt. Ist für dieses Konto ein Passkey eingerichtet?");
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
      className="relative flex min-h-dvh flex-col items-center justify-center px-4 py-10"
      style={{
        backgroundImage:
          "radial-gradient(60rem 36rem at 15% -10%, color-mix(in srgb, var(--accent) 18%, transparent), transparent 70%), radial-gradient(48rem 30rem at 100% 110%, color-mix(in srgb, var(--accent) 14%, transparent), transparent 70%), radial-gradient(color-mix(in srgb, var(--text-3) 30%, transparent) 1px, transparent 1px)",
        backgroundSize: "auto, auto, 22px 22px",
      }}
    >
      <Orbits />
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
          className="relative flex flex-col gap-4 overflow-hidden rounded-xl border border-line bg-[color-mix(in_srgb,var(--surface)_82%,transparent)] p-6 shadow-(--shadow-float) backdrop-blur-md"
        >
          {/* Leuchtkante oben, wie bei modernen Anmeldedialogen */}
          <span aria-hidden="true" className="pointer-events-none absolute inset-x-8 top-0 h-px bg-linear-to-r from-transparent via-accent to-transparent opacity-70" />
          <div className="mb-1 text-center">
            <h2 className="m-0 text-lg font-semibold">Willkommen zurück</h2>
            <p className="m-0 mt-1 text-xs text-fg3">Melde dich an, um deine Hosts und CVEs zu sehen.</p>
          </div>
          <label className="relative block">
            <span className="sr-only">Benutzername</span>
            <TextInput name="username" placeholder="Benutzername" autoComplete="username" autoCapitalize="none" spellCheck={false} required maxLength={64} className="h-12! w-full rounded-2xl! border-transparent! bg-[color-mix(in_srgb,var(--text)_7%,transparent)]! pl-11 text-base! focus-visible:border-accent!" />
            <svg aria-hidden="true" focusable="false" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className="pointer-events-none absolute left-4 top-1/2 -translate-y-1/2 text-fg3">
              <circle cx="12" cy="8" r="4" />
              <path d="M4 21c1-4 4-6 8-6s7 2 8 6" />
            </svg>
          </label>
          {/* Der Umschalter liegt außerhalb des <label>, damit der Name des Feldes „Passwort“ bleibt. */}
          <div className="relative">
            <label className="relative block">
              <span className="sr-only">Passwort</span>
              <TextInput name="password" placeholder="Passwort" type={show ? "text" : "password"} autoComplete="current-password" required maxLength={256} className="h-12! w-full rounded-2xl! border-transparent! bg-[color-mix(in_srgb,var(--text)_7%,transparent)]! pl-11 text-base! focus-visible:border-accent! pr-14" />
              <svg aria-hidden="true" focusable="false" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className="pointer-events-none absolute left-4 top-1/2 -translate-y-1/2 text-fg3">
                <rect x="4" y="11" width="16" height="10" rx="2" />
                <path d="M8 11V8a4 4 0 018 0v3" />
              </svg>
            </label>
            <Button
              variant="ghost"
              data-hit="none"
              aria-pressed={show}
              aria-label={show ? "Eingabe verbergen" : "Eingabe anzeigen"}
              onClick={() => setShow(!show)}
              className="absolute right-2 top-1/2 h-9! min-h-0! w-10! min-w-0! -translate-y-1/2 border-0! px-0! text-fg3 hover:text-fg max-md:h-11! max-md:w-11!"
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
          <Button type="submit" variant="primary" busy={busy} disabled={!hydrated} className="h-12! w-full rounded-2xl!">
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
                  onClick={() => void passkeyLogin()}
                  title={webauthnSupported() ? undefined : "Dieser Browser unterstützt keine Passkeys (oder die Seite läuft nicht über HTTPS)."}
                  className="h-12! w-full rounded-2xl!"
                >
                  Mit Passkey anmelden
                </Button>
              ) : null}
              {oidc?.enabled ? (
              <a
                href="/api/v1/auth/oidc/login"
                className="inline-flex h-12 items-center justify-center rounded-2xl border border-control bg-surface px-3 font-semibold no-underline hover:border-accent max-md:min-h-11"
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
