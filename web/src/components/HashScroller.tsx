"use client";

import { useEffect } from "react";
import { usePathname } from "next/navigation";
import { toast } from "@/lib/toastStore";
import { can } from "@/lib/roles";
import { useAuth } from "@/components/AuthProvider";

/** Anker, die nur mit einem bestimmten Recht sichtbar sind: ohne Recht eine freundliche Meldung statt eines leeren Bildschirms. */
const GATED: Record<string, { perm: string; text: string }> = {
  oidc: { perm: "oidc.manage", text: "Dieser Abschnitt ist nur mit dem Recht „OIDC einrichten“ sichtbar." },
};

const WAIT_MS = 3000; // Abschnitte erscheinen oft erst nach den Skeletons
const FLASH_MS = 1500;
const SETTLE_MS = 2500;

/** Spring zum Ziel eines Ankers: wartet bis das Element existiert, scrollt unter die feste Kopfzeile, fokussiert die Überschrift, hebt kurz hervor. */
export function scrollToHash(id: string, opts?: { reduced?: boolean; onMissing?: () => void }): () => void {
  const reduced = opts?.reduced ?? window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  let done = false;
  let flashTimer: number | undefined;
  let settleTimer: number | undefined;
  let stopSettle = () => {};
  const go = (anchor: HTMLElement) => {
    done = true;
    // Ist der Anker eine Überschrift, wird ihr Abschnitt hervorgehoben und angescrollt.
    const el = anchor.matches("h1,h2,h3") ? (anchor.closest<HTMLElement>("section") ?? anchor) : anchor;
    const bar = document.querySelector("header.sticky");
    el.style.scrollMarginTop = `${(bar instanceof HTMLElement ? bar.offsetHeight : 0) + 16}px`;
    el.scrollIntoView({ behavior: reduced ? "instant" : "smooth", block: "start" });
    // Lädt Inhalt oberhalb des Ziels nach (Skeletons werden zu Tabellen), verschiebt sich das Ziel: nachführen,
    // solange die Person nicht selbst scrollt und höchstens SETTLE_MS lang.
    let touched = false;
    const mark = () => {
      touched = true;
    };
    const evts = ["wheel", "touchstart", "keydown", "pointerdown"] as const;
    for (const e of evts) window.addEventListener(e, mark, { passive: true, once: true });
    const settle = new ResizeObserver(() => {
      if (!touched) el.scrollIntoView({ behavior: "instant", block: "start" });
    });
    settle.observe(document.body);
    settleTimer = window.setTimeout(() => {
      settle.disconnect();
      for (const e of evts) window.removeEventListener(e, mark);
    }, SETTLE_MS);
    stopSettle = () => {
      settle.disconnect();
      window.clearTimeout(settleTimer);
      for (const e of evts) window.removeEventListener(e, mark);
    };
    const heading = el.matches("h1,h2,h3") ? el : el.querySelector<HTMLElement>("h1,h2,h3");
    const focusEl = heading ?? el;
    if (!focusEl.hasAttribute("tabindex")) focusEl.setAttribute("tabindex", "-1");
    focusEl.focus({ preventScroll: true });
    el.style.transition = reduced ? "none" : "box-shadow 300ms ease-out, background-color 300ms ease-out";
    el.setAttribute("data-hash-target", "");
    flashTimer = window.setTimeout(() => el.removeAttribute("data-hash-target"), FLASH_MS);
  };
  const find = () => document.getElementById(id);
  const now = find();
  if (now) {
    go(now);
    return () => {
      window.clearTimeout(flashTimer);
      stopSettle();
    };
  }
  const obs = new MutationObserver(() => {
    const el = find();
    if (el && !done) {
      obs.disconnect();
      window.clearTimeout(timer);
      go(el);
    }
  });
  obs.observe(document.body, { childList: true, subtree: true });
  const timer = window.setTimeout(() => {
    obs.disconnect();
    if (!done) opts?.onMissing?.();
  }, WAIT_MS);
  return () => {
    done = true;
    obs.disconnect();
    window.clearTimeout(timer);
    window.clearTimeout(flashTimer);
    stopSettle();
  };
}

/** Im App-Layout einmal eingebunden: gilt für alle internen Links mit Anker, direkten Aufruf und Ankerwechsel auf derselben Seite. */
export function HashScroller() {
  const pathname = usePathname();
  const { me } = useAuth();
  const perms = me?.permissions;
  useEffect(() => {
    let stop = () => {};
    const run = () => {
      stop();
      const id = decodeURIComponent(window.location.hash.slice(1));
      if (!id) return;
      stop = scrollToHash(id, {
        onMissing: () => {
          const g = GATED[id];
          if (g && !can(perms, g.perm)) toast.info(g.text);
        },
      });
    };
    run();
    // Next ändert den Anker per pushState (kein hashchange): Verlaufsfunktionen so umhüllen, dass derselbe Weg läuft.
    const push = history.pushState.bind(history);
    const origPush = history.pushState;
    history.pushState = (...a: Parameters<History["pushState"]>) => {
      push(...a);
      window.setTimeout(run, 0);
    };
    window.addEventListener("hashchange", run);
    return () => {
      history.pushState = origPush;
      window.removeEventListener("hashchange", run);
      stop();
    };
  }, [pathname, perms]);
  return null;
}
