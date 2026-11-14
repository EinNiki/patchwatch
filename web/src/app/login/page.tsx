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

/** Bahnen (echte Kreise): Radius relativ zur kleineren Fensterseite (k), Umlaufzeit in s (negativ = gegen den Uhrzeigersinn). */
const RINGS: { k: number; period: number; icons: string[] }[] = [
  { k: 0.45, period: 70, icons: ["Ubuntu", "Debian", "Fedora"] },
  { k: 0.52, period: -90, icons: ["Alpine", "Arch", "Proxmox"] },
  { k: 0.59, period: 120, icons: ["RHEL", "openSUSE"] },
];

const ICON = 40; // Durchmesser in px

/** Startwinkel eines Logos auf seiner Bahn. */
const baseAngle = (ri: number, i: number) => (i / RINGS[ri]!.icons.length) * Math.PI * 2 + ri;

/**
 * Logos kreisen auf unsichtbaren Kreisbahnen um die Anmeldekarte. Sie lassen sich anfassen und werfen: ein
 * losgelassenes Logo fliegt mit seinem Schwung weiter, prallt an den Fensterrändern ab, wird von einer weichen Feder
 * zur Kreisbahn gezogen und reiht sich dort am nächstgelegenen Punkt wieder ein (nicht an seiner alten Stelle).
 * Die Bahn-Mitte folgt dem Mauszeiger ein paar Pixel. Die Startpositionen stehen schon im Server-HTML (CSS), damit
 * nichts erst nach dem Laden des Skripts erscheint. „Weniger Bewegung“: Logos stehen still und lassen sich nicht werfen.
 * Reine Dekoration (aria-hidden).
 */
function Orbits() {
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = box.current;
    if (!el || window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const icons = Array.from(el.querySelectorAll<HTMLElement>("[data-orbit]"));
    // theta: Winkel auf der Bahn (nur im Umlauf); x/y: Position zur Mitte; free: fliegt gerade frei (geworfen/gezogen)
    const st = icons.map((c) => ({ theta: baseAngle(Number(c.dataset.ring), Number(c.dataset.i)), x: 0, y: 0, vx: 0, vy: 0, free: false }));
    let target = { x: 0, y: 0 };
    const cur = { x: 0, y: 0 };
    const size = { w: 0, h: 0 };
    let drag: { i: number; id: number; gx: number; gy: number; px: number; py: number } | null = null;

    const radius = (ri: number) => {
      // Handy (hochkant): Radius nach der Höhe, damit die Logos oben und unten neben der Karte laufen statt dahinter.
      const m = size.w < 768 ? size.h : Math.min(size.w, size.h);
      return RINGS[ri]!.k * m;
    };

    const rel = (e: PointerEvent, gx: number, gy: number) => {
      const r = el.getBoundingClientRect();
      return { x: e.clientX - r.left - r.width / 2 - cur.x - gx, y: e.clientY - r.top - r.height / 2 - cur.y - gy };
    };
    const move = (e: PointerEvent) => {
      if (e.pointerType === "mouse") {
        const r = el.getBoundingClientRect();
        target = { x: ((e.clientX - r.left) / r.width - 0.5) * 36, y: ((e.clientY - r.top) / r.height - 0.5) * 36 };
      }
      if (drag && e.pointerId === drag.id) {
        const q = rel(e, drag.gx, drag.gy);
        drag.px = q.x;
        drag.py = q.y;
      }
    };
    const up = (e: PointerEvent) => {
      if (drag && e.pointerId === drag.id) {
        icons[drag.i]!.style.cursor = "grab";
        drag = null; // free bleibt gesetzt: das Logo fliegt mit dem zuletzt gemessenen Schwung weiter
      }
    };
    const downs = icons.map((c, i) => {
      const f = (e: PointerEvent) => {
        if (e.button > 0) return;
        const cr = c.getBoundingClientRect();
        const gx = e.clientX - (cr.left + cr.width / 2);
        const gy = e.clientY - (cr.top + cr.height / 2);
        const q = rel(e, gx, gy);
        drag = { i, id: e.pointerId, gx, gy, px: q.x, py: q.y };
        const s = st[i]!;
        s.free = true;
        s.vx = 0;
        s.vy = 0;
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
    let last = 0;
    const tick = (t: number) => {
      const dt = Math.min((t - (last || t)) / 1000, 0.04) || 0.016;
      last = t;
      size.w = el.clientWidth;
      size.h = el.clientHeight;
      cur.x += (target.x - cur.x) * 0.05;
      cur.y += (target.y - cur.y) * 0.05;
      el.style.setProperty("--ox", `${cur.x.toFixed(1)}px`);
      el.style.setProperty("--oy", `${cur.y.toFixed(1)}px`);
      const hx = size.w / 2 - ICON / 2 - 4;
      const hy = size.h / 2 - ICON / 2 - 4;
      icons.forEach((c, i) => {
        const s = st[i]!;
        const ri = Number(c.dataset.ring);
        const R = radius(ri);
        if (drag && drag.i === i) {
          // Folgt dem Zeiger; Geschwindigkeit weich mitschreiben, damit der Wurf Schwung hat.
          s.vx += ((drag.px - s.x) / dt - s.vx) * 0.35;
          s.vy += ((drag.py - s.y) / dt - s.vy) * 0.35;
          s.x = drag.px;
          s.y = drag.py;
        } else if (s.free) {
          // Frei: Feder zur Kreisbahn (nur radial) plus Reibung; der Schwung bleibt zunächst erhalten.
          const r = Math.hypot(s.x, s.y);
          const ux = r > 1 ? s.x / r : 1;
          const uy = r > 1 ? s.y / r : 0;
          const K = 7;
          const C = 2.2;
          s.vx += (-K * (r - R) * ux - C * s.vx) * dt;
          s.vy += (-K * (r - R) * uy - C * s.vy) * dt;
          const v = Math.hypot(s.vx, s.vy);
          if (v > 3000) {
            s.vx *= 3000 / v;
            s.vy *= 3000 / v;
          }
          s.x += s.vx * dt;
          s.y += s.vy * dt;
          // Eingereiht, sobald das Logo nahe an der Bahn und langsam ist: Umlauf startet am aktuellen Winkel.
          if (Math.abs(Math.hypot(s.x, s.y) - R) < 8 && Math.hypot(s.vx, s.vy) < 90) {
            s.free = false;
            s.theta = Math.atan2(s.y, s.x);
          }
        } else {
          s.theta += ((Math.PI * 2) / RINGS[ri]!.period) * dt;
          s.x = Math.cos(s.theta) * R;
          s.y = Math.sin(s.theta) * R;
        }
        // Abprallen an den Fensterrändern (nur beim Ziehen/Fliegen; im Umlauf dürfen Logos seitlich aus dem Bild laufen).
        if (!drag && !s.free) {
          c.style.transform = `translate3d(${s.x.toFixed(1)}px, ${s.y.toFixed(1)}px, 0)`;
          return;
        }
        if (s.x > hx || s.x < -hx) {
          s.x = Math.max(-hx, Math.min(hx, s.x));
          if (!(drag && drag.i === i)) s.vx *= -0.75;
        }
        if (s.y > hy || s.y < -hy) {
          s.y = Math.max(-hy, Math.min(hy, s.y));
          if (!(drag && drag.i === i)) s.vy *= -0.75;
        }
        c.style.transform = `translate3d(${s.x.toFixed(1)}px, ${s.y.toFixed(1)}px, 0)`;
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
                // Startposition schon im HTML (siehe .orbit-icon in globals.css): das Skript übernimmt nahtlos.
                style={
                  {
                    left: -ICON / 2,
                    top: -ICON / 2,
                    "--c": Math.cos(a).toFixed(3),
                    "--s": Math.sin(a).toFixed(3),
                    "--k": ring.k,
                  } as React.CSSProperties
                }
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
      <div className="relative w-full max-w-md">
        <div className="mb-6 flex flex-col items-center text-center">
          <svg width="56" height="56" viewBox="0 0 32 32" aria-hidden="true" focusable="false" className="mb-3 rounded-lg shadow-(--shadow-float)">
            <rect width="32" height="32" rx="6" fill="var(--accent)" />
            <path d="M9 16.5l4.5 4.5L23 11" fill="none" stroke="var(--bg)" strokeWidth="3.2" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          <h1 className="m-0 font-mono text-2xl font-medium">patchwatch</h1>
        </div>
        {/* method="post": Selbst wenn JavaScript fehlt, landen Zugangsdaten nie in der URL. */}
        <form
          method="post"
          action="/login"
          onSubmit={(e) => void submit(e)}
          className="flex flex-col gap-4 rounded-lg border border-line bg-surface p-8 shadow-(--shadow-float) max-sm:p-6"
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
                  // Bei großer Schrift darf der Text umbrechen statt abgeschnitten zu werden.
                  className="h-auto! min-h-8 w-full whitespace-normal! py-1.5 leading-tight max-md:min-h-11"
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
