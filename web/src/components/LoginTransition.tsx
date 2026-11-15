"use client";

import { useEffect, useSyncExternalStore } from "react";
import { usePathname, useRouter } from "next/navigation";
import { LOGIN_BG } from "@/lib/loginBg";
import { clearApiCache } from "@/lib/apiCache";
import { getLoginPhase, getOrigin, setLoginPhase, subscribeLoginPhase, whenLogoutDone } from "@/lib/loginTransition";

/**
 * Übergänge bei An- und Abmeldung. Liegt im Wurzel-Layout und bleibt deshalb beim Seitenwechsel bestehen.
 * Anmeldung: Overlay (gleicher Hintergrund wie die Anmeldeseite, also nahtlos) deckt, dann öffnet sich ein Loch von der
 * Mitte aus und gibt das Dashboard frei. Abmeldung: ein Kreis wächst von der Abmelden-Taste aus über den Bildschirm,
 * darunter lädt die Anmeldeseite, dann blendet das Overlay aus. Rein dekorativ.
 */
export function LoginTransition() {
  const phase = useSyncExternalStore(subscribeLoginPhase, getLoginPhase, () => "idle" as const);
  const path = usePathname();
  const router = useRouter();
  useEffect(() => {
    if (phase === "cover") {
      if (path !== "/login") {
        // Dashboard ist geladen: kurz warten, damit es unter dem Overlay fertig steht, dann aufmachen.
        const t = setTimeout(() => setLoginPhase("reveal"), 450);
        return () => clearTimeout(t);
      }
      const t = setTimeout(() => setLoginPhase("idle"), 8000); // Sicherung: Wechsel kam nicht zustande
      return () => clearTimeout(t);
    }
    if (phase === "reveal" || phase === "fade") {
      const t = setTimeout(() => setLoginPhase("idle"), 2000);
      return () => clearTimeout(t);
    }
    if (phase === "away") {
      if (path === "/login") {
        const t = setTimeout(() => setLoginPhase("fade"), 120);
        return () => clearTimeout(t);
      }
      const t = setTimeout(() => setLoginPhase("idle"), 8000);
      return () => clearTimeout(t);
    }
  }, [phase, path]);
  if (phase === "idle") return null;
  const o = getOrigin();
  const cls = phase === "reveal" ? "login-reveal" : phase === "out" ? "login-out" : phase === "fade" ? "login-reveal" : "";
  return (
    <div
      aria-hidden="true"
      style={{ ...LOGIN_BG, ...(phase === "out" ? ({ "--ox": `${o.x}px`, "--oy": `${o.y}px` } as React.CSSProperties) : null) }}
      className={`fixed inset-0 z-[100] ${cls}`}
      onAnimationEnd={() => {
        if (phase === "reveal" || phase === "fade") setLoginPhase("idle");
        if (phase === "out") {
          whenLogoutDone(() => {
            clearApiCache();
            setLoginPhase("away");
            router.replace("/login");
          });
        }
      }}
    />
  );
}
