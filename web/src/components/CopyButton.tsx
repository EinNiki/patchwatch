"use client";

import { useEffect, useRef, useState } from "react";
import { browserEnv, copyText } from "@/lib/clipboard";
import { toast } from "@/lib/toastStore";

/** Zwischenablage-Symbol und Haken (Inline-SVG, 16 px, Linienstärke 1.5, currentColor). */
function CopyIcon({ done }: { done: boolean }) {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false">
      {done ? (
        <path d="M3 8.5 6.5 12 13 4.5" />
      ) : (
        <>
          <rect x="5.25" y="2.75" width="7.5" height="10.5" rx="1.25" />
          <path d="M3.25 10.75V4.25a1.5 1.5 0 0 1 1.5-1.5H5.5" />
        </>
      )}
    </svg>
  );
}

/**
 * Nur-Symbol-Knopf zum Kopieren. Sichtbar 24 px hoch (passt zur Zeilenhöhe), die Trefferfläche wächst mobil unsichtbar auf 44 px.
 * Nach dem Klick 1,5 s ein Haken und ein Erfolgs-Toast. Ohne Clipboard-API greift der Rückfall; klappt auch der nicht,
 * wird der Text über `onSelect` markiert und ein Warn-Toast zeigt den Weg (Strg+C).
 */
export function CopyButton({ text, label = "Kopieren", onSelect }: { text: string; label?: string; onSelect?: () => void }) {
  const [done, setDone] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(
    () => () => {
      if (timer.current) clearTimeout(timer.current);
    },
    [],
  );
  async function copy(e: React.MouseEvent<HTMLButtonElement>) {
    const host = e.currentTarget.closest("dialog") ?? undefined;
    const result = await copyText(text, browserEnv(host as HTMLElement | undefined));
    if (result === "failed") {
      onSelect?.();
      toast.warning("Kopieren nicht möglich. Text markiert, mit Strg+C kopieren.");
      return;
    }
    toast.success("In die Zwischenablage kopiert");
    setDone(true);
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => setDone(false), 1500);
  }
  return (
    <button
      type="button"
      onClick={(e) => void copy(e)}
      aria-label={label}
      title={label}
      className="inline-flex size-6 max-md:size-11 shrink-0 items-center justify-center rounded-xs text-fg2 hover:bg-sunk hover:text-fg"
    >
      <CopyIcon done={done} />
      <span role="status" aria-live="polite" className="sr-only">
        {done ? "In die Zwischenablage kopiert" : ""}
      </span>
    </button>
  );
}

/**
 * Befehl oder Token im eigenen Codefeld (Monospace, eigener Hintergrund, 1 px Rand, Radius wie Controls) mit dem Kopier-Symbol
 * am rechten Ende innerhalb des Feldes. Lange Werte brechen um; die Seite scrollt nie seitwärts.
 */
export function CodeField({ text, label = "Befehl kopieren", inline = false, className = "" }: { text: string; label?: string; inline?: boolean; className?: string }) {
  const code = useRef<HTMLElement>(null);
  function select() {
    const el = code.current;
    const sel = window.getSelection();
    if (!el || !sel) return;
    sel.removeAllRanges();
    const r = document.createRange();
    r.selectNodeContents(el);
    sel.addRange(r);
  }
  return (
    <span className={`${inline ? "inline-flex" : "flex"} max-w-full min-w-0 items-start gap-1 rounded-[3px] border border-line bg-sunk py-0.5 pl-2 pr-1 align-middle ${className}`}>
      <code ref={code} className="mono min-w-0 flex-1 break-all py-px leading-5 text-fg">
        {text}
      </code>
      <CopyButton text={text} label={label} onSelect={select} />
    </span>
  );
}
