"use client";

import { useSyncExternalStore } from "react";
import { Button } from "@/components/Controls";

/** Ob gerade das dunkle Design gilt (gewählt oder vom System). */
function isDark() {
  const t = document.documentElement.getAttribute("data-theme");
  return t ? t === "dark" : window.matchMedia("(prefers-color-scheme: dark)").matches;
}

/** Beobachtet das gesetzte Design (data-theme) und die Systemeinstellung. */
function subscribe(cb: () => void) {
  const mo = new MutationObserver(cb);
  mo.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
  const mq = window.matchMedia("(prefers-color-scheme: dark)");
  mq.addEventListener("change", cb);
  return () => {
    mo.disconnect();
    mq.removeEventListener("change", cb);
  };
}

/** Schalter Hell/Dunkel für Seiten ohne Einstellungen (Anmeldung). Teilt „pw-theme“ mit der Auswahl unter Einstellungen. */
export function ThemeToggle({ className = "" }: { className?: string }) {
  const dark = useSyncExternalStore(subscribe, isDark, () => false);
  const toggle = () => {
    const next = dark ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    try {
      localStorage.setItem("pw-theme", next);
    } catch {
      /* Speicher gesperrt: gilt nur für diese Sitzung */
    }
  };
  return (
    <Button
      variant="ghost"
      onClick={toggle}
      aria-label={dark ? "Helles Design einschalten" : "Dunkles Design einschalten"}
      title={dark ? "Helles Design" : "Dunkles Design"}
      className={`size-11! min-h-0! w-11! min-w-0! rounded-full! px-0! ${className}`}
    >
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false">
        {dark ? (
          <>
            <circle cx="12" cy="12" r="4" />
            <path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" />
          </>
        ) : (
          <path d="M21 12.8A9 9 0 1111.2 3a7 7 0 009.8 9.8z" />
        )}
      </svg>
    </Button>
  );
}
