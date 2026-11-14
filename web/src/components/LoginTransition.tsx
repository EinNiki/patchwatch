"use client";

import { useEffect, useSyncExternalStore } from "react";
import { usePathname } from "next/navigation";
import { LOGIN_BG } from "@/lib/loginBg";
import { getLoginPhase, setLoginPhase, subscribeLoginPhase } from "@/lib/loginTransition";

/**
 * Übergang nach der Anmeldung. Liegt im Wurzel-Layout und bleibt deshalb beim Seitenwechsel bestehen: erst deckt das
 * Overlay (gleicher Hintergrund wie die Anmeldeseite, also nahtlos), dann öffnet sich ein Loch von der Mitte aus und
 * gibt das Dashboard frei. Rein dekorativ; ohne „weniger Bewegung“-Wunsch.
 */
export function LoginTransition() {
  const phase = useSyncExternalStore(subscribeLoginPhase, getLoginPhase, () => "idle" as const);
  const path = usePathname();
  useEffect(() => {
    if (phase === "cover" && path !== "/login") {
      // Dashboard ist geladen: kurz warten, damit es unter dem Overlay fertig steht, dann aufmachen.
      const t = setTimeout(() => setLoginPhase("reveal"), 450);
      return () => clearTimeout(t);
    }
    if (phase === "cover") {
      // Sicherung: Wechsel kam nicht zustande.
      const t = setTimeout(() => setLoginPhase("idle"), 8000);
      return () => clearTimeout(t);
    }
    if (phase === "reveal") {
      const t = setTimeout(() => setLoginPhase("idle"), 1200);
      return () => clearTimeout(t);
    }
  }, [phase, path]);
  if (phase === "idle") return null;
  return (
    <div
      aria-hidden="true"
      style={LOGIN_BG}
      className={`fixed inset-0 z-[100] ${phase === "reveal" ? "login-reveal" : ""}`}
      onAnimationEnd={() => phase === "reveal" && setLoginPhase("idle")}
    >
      <span className="absolute left-1/2 top-1/2 size-3 -translate-x-1/2 -translate-y-1/2 rounded-full bg-accent shadow-[0_0_40px_14px_color-mix(in_srgb,var(--accent)_55%,transparent)]" />
    </div>
  );
}
