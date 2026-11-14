"use client";

import { useEffect, useRef, useState, useSyncExternalStore } from "react";
import { useRouter } from "next/navigation";
import { api, ApiError, setCsrf } from "@/lib/api";
import type { Me } from "@/lib/types";
import { Button, Field, TextInput } from "@/components/Controls";
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

const ICON = 40; // Durchmesser in px
const MARGIN = 26; // Mindestabstand zum Fensterrand beim Werfen

/** Startwinkel eines Logos auf seiner Bahn. */
const baseAngle = (ri: number, i: number) => (i / RINGS[ri]!.icons.length) * Math.PI * 2 + ri;

/**
 * Logos kreisen (ohne sichtbare Linien) in Abstand um die Anmeldekarte. Sie lassen sich anfassen und werfen: beim
 * Loslassen behält ein Logo seinen Schwung, prallt an den Fensterrändern ab und wird von einer weichen Feder zurück
 * auf seine Bahn gezogen. Die Bahn-Mitte folgt dem Mauszeiger ein paar Pixel. Die Startpositionen stehen schon im
 * Server-HTML (CSS), damit nichts erst nach dem Laden des Skripts erscheint; „weniger Bewegung“: Logos stehen still und
 * lassen sich nicht werfen. Reine Dekoration (aria-hidden), per Tastatur nicht nötig.
 */
function Orbits() {
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = box.current;
    if (!el || window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const icons = Array.from(el.querySelectorAll<HTMLElement>("[data-orbit]"));
    const st = icons.map(() => ({ x: 0, y: 0, vx: 0, vy: 0 })); // Abweichung von der Bahn (px) und Geschwindigkeit
    let target = { x: 0, y: 0 };
    const cur = { x: 0, y: 0 };
    const size = { w: 0, h: 0 };
    let drag: { i: number; id: number; gx: number; gy: number; px: number; py: number; pt: number } | null = null;
    let tilt = { x: 0, y: 0 };

    const orbitPos = (i: number, t0: number) => {
      const c = icons[i]!;
      const ri = Number(c.dataset.ring);
      const ring = RINGS[ri]!;
      const a = baseAngle(ri, Number(c.dataset.i)) + (t0 / 1000 / ring.period) * Math.PI * 2;
      let rx = Math.max(size.w * ring.k, 250 + ri * 60);
      let ry = size.h * ring.k;
      // Schmale Fenster (Handy): Bahnen bleiben komplett im Bild.
      if (size.w < 768) {
        rx = Math.min(rx, size.w / 2 - MARGIN);
        ry = Math.min(ry, size.h / 2 - MARGIN);
      }
      return { x: Math.cos(a) * rx, y: Math.sin(a) * ry };
    };

    const move = (e: PointerEvent) => {
      if (e.pointerType === "mouse") {
        const r = el.getBoundingClientRect();
        target = { x: ((e.clientX - r.left) / r.width - 0.5) * 36, y: ((e.clientY - r.top) / r.height - 0.5) * 36 };
      }
      if (drag && e.pointerId === drag.id) {
        // Zeigerposition relativ zur Mitte der Fläche, ohne die Neigung.
        const r = el.getBoundingClientRect();
        drag.px = e.clientX - r.left - r.width / 2 - tilt.x - drag.gx;
        drag.py = e.clientY - r.top - r.height / 2 - tilt.y - drag.gy;
      }
    };
    const up = (e: PointerEvent) => {
      if (drag && e.pointerId === drag.id) {
        icons[drag.i]!.style.cursor = "grab";
        drag = null; // die Geschwindigkeit stammt aus den letzten Bewegungen (siehe tick)
      }
    };
    const downs = icons.map((c, i) => {
      const f = (e: PointerEvent) => {
        if (e.button > 0) return;
        const r = el.getBoundingClientRect();
        const cr = c.getBoundingClientRect();
        // Griffpunkt: Abstand des Zeigers zur Mitte des Logos.
        const gx = e.clientX - (cr.left + cr.width / 2);
        const gy = e.clientY - (cr.top + cr.height / 2);
        drag = { i, id: e.pointerId, gx, gy, px: e.clientX - r.left - r.width / 2 - tilt.x - gx, py: e.clientY - r.top - r.height / 2 - tilt.y - gy, pt: performance.now() };
        st[i]!.vx = 0;
        st[i]!.vy = 0;
        c.style.cursor = "grabbing";
        c.setPointerCapture(e.pointerId);
        e.preventDefault();
      };
      c.addEventListener("pointerdown", f);
      return f;
    });
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
    window.addEventListener("pointercancel", up);

    let raf = 0;
    let t0 = 0;
    let last = 0;
    const tick = (t: number) => {
      if (!t0) {
        t0 = t;
        last = t;
      }
      const dt = Math.min((t - last) / 1000, 0.04) || 0.016;
      last = t;
      size.w = el.clientWidth;
      size.h = el.clientHeight;
      cur.x += (target.x - cur.x) * 0.05;
      cur.y += (target.y - cur.y) * 0.05;
      tilt = cur;
      el.style.setProperty("--ox", `${cur.x.toFixed(1)}px`);
      el.style.setProperty("--oy", `${cur.y.toFixed(1)}px`);
      const hx = size.w / 2 - ICON / 2 - 4;
      const hy = size.h / 2 - ICON / 2 - 4;
      icons.forEach((c, i) => {
        const o = orbitPos(i, t - t0);
        const s = st[i]!;
        if (drag && drag.i === i) {
          // Folgt dem Zeiger; die Geschwindigkeit wird weich mitgeschrieben, damit der Wurf Schwung hat.
          const nx = drag.px - o.x;
          const ny = drag.py - o.y;
          s.vx += ((nx - s.x) / dt - s.vx) * 0.35;
          s.vy += ((ny - s.y) / dt - s.vy) * 0.35;
          s.x = nx;
          s.y = ny;
        } else {
          // Weiche Feder zurück auf die Bahn (leicht unterdämpft: schwingt kurz nach) und Reibung.
          const K = 2.4;
          const C = 1.5;
          s.vx += (-K * s.x - C * s.vx) * dt;
          s.vy += (-K * s.y - C * s.vy) * dt;
          s.vx = Math.max(-3000, Math.min(3000, s.vx));
          s.vy = Math.max(-3000, Math.min(3000, s.vy));
          s.x += s.vx * dt;
          s.y += s.vy * dt;
        }
        // Abprallen an den Fensterrändern (absolute Position = Bahn + Abweichung).
        let ax = o.x + s.x;
        let ay = o.y + s.y;
        if (ax > hx || ax < -hx) {
          ax = Math.max(-hx, Math.min(hx, ax));
          if (!(drag && drag.i === i)) s.vx *= -0.75;
          s.x = ax - o.x;
        }
        if (ay > hy || ay < -hy) {
          ay = Math.max(-hy, Math.min(hy, ay));
          if (!(drag && drag.i === i)) s.vy *= -0.75;
          s.y = ay - o.y;
        }
        c.style.transform = `translate3d(${ax.toFixed(1)}px, ${ay.toFixed(1)}px, 0)`;
      });
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    icons.forEach((c) => {
      c.style.cursor = "grab";
      c.style.pointerEvents = "auto";
    });
    return () => {
      cancelAnimationFrame(raf);
      icons.forEach((c, i) => c.removeEventListener("pointerdown", downs[i]!));
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
      window.removeEventListener("pointercancel", up);
    };
  }, []);
  return (
    <div ref={box} aria-hidden="true" className="pointer-events-none absolute inset-0 overflow-hidden">
      <div className="absolute left-1/2 top-1/2" style={{ transform: "translate(var(--ox, 0px), var(--oy, 0px))" }}>
        {RINGS.map((ring, ri) =>
          ring.icons.map((name, i) => {
            const a = baseAngle(ri, i);
            return (
              <span
                key={name}
                data-orbit
                data-ring={ri}
                data-i={i}
                className="orbit-icon absolute touch-none select-none will-change-transform"
                // Startposition schon im HTML: das Skript übernimmt nahtlos, die Logos stehen sofort da.
                style={{
                  left: -ICON / 2,
                  top: -ICON / 2,
                  transform: `translate3d(calc(${Math.cos(a).toFixed(3)} * max(${ring.k * 100}vw, ${250 + ri * 60}px)), calc(${Math.sin(a).toFixed(3)} * ${ring.k * 100}vh), 0)`,
                }}
              >
                <span className="flex size-10 items-center justify-center rounded-full border border-line bg-surface shadow-(--shadow-float)">
                  <svg viewBox="0 0 24 24" className="size-5" fill={DISTRO_ICONS[name]!.hex}>
                    <path d={DISTRO_ICONS[name]!.path} />
                  </svg>
                </span>
              </span>
            );
          }),
        )}
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
          "radial-gradient(52rem 34rem at 100% -6%, color-mix(in srgb, color-mix(in srgb, var(--accent) 45%, #a9d0ff) 26%, transparent), transparent 70%), radial-gradient(52rem 34rem at 100% 106%, color-mix(in srgb, color-mix(in srgb, var(--accent) 45%, #a9d0ff) 22%, transparent), transparent 70%), radial-gradient(color-mix(in srgb, var(--text-3) 30%, transparent) 1px, transparent 1px)",
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
                  onClick={() => void passkeyLogin()}
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
