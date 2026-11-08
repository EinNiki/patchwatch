"use client";

import { useCallback, useEffect, useId, useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";

/** Was der Auslöser braucht, um Popover und Zustand zu verbinden. */
export interface PopoverTrigger {
  ref: React.RefObject<HTMLButtonElement | null>;
  open: boolean;
  toggle: () => void;
  close: () => void;
  "aria-haspopup": "dialog";
  "aria-expanded": boolean;
  "aria-controls": string | undefined;
}

/**
 * Gemeinsame Popover-Logik für Filter, „+N“-Listen und Menüs: Fenster am Auslöser (im Body, damit keine Tabelle es
 * abschneidet), Schließen per Klick daneben und Escape, Fokus kehrt zum Auslöser zurück. Auf schmalen Bildschirmen
 * erscheint es als Bottom-Sheet mit Hintergrund. Nicht modal: die Seite dahinter bleibt bedienbar.
 */
export function Popover({
  label,
  trigger,
  children,
  align = "start",
  width = 288,
  sheet = true,
  onOpenChange,
}: {
  /** Zugänglicher Name des Fensters. */
  label: string;
  trigger: (t: PopoverTrigger) => React.ReactNode;
  children: React.ReactNode | ((close: () => void) => React.ReactNode);
  align?: "start" | "end";
  width?: number;
  /** Mobil als Bottom-Sheet (Standard); aus = bleibt ein kleines Fenster am Auslöser. */
  sheet?: boolean;
  onOpenChange?: (open: boolean) => void;
}) {
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<{ top: number; left: number } | null>(null);
  const btn = useRef<HTMLButtonElement | null>(null);
  const panel = useRef<HTMLDivElement | null>(null);
  const id = useId();

  const set = useCallback(
    (v: boolean) => {
      setOpen(v);
      onOpenChange?.(v);
    },
    [onOpenChange],
  );
  const close = useCallback(() => set(false), [set]);

  // Position unter dem Auslöser; bei Scrollen/Größenänderung nachführen (fixed im Body).
  const place = useCallback(() => {
    const b = btn.current?.getBoundingClientRect();
    if (!b) return;
    const w = Math.min(width, window.innerWidth - 16);
    const left = align === "end" ? b.right - w : b.left;
    setPos({ top: b.bottom + 6, left: Math.max(8, Math.min(left, window.innerWidth - w - 8)) });
  }, [align, width]);
  useLayoutEffect(() => {
    if (open) place();
  }, [open, place]);
  useEffect(() => {
    if (!open) return;
    const on = () => place();
    window.addEventListener("resize", on);
    window.addEventListener("scroll", on, true);
    return () => {
      window.removeEventListener("resize", on);
      window.removeEventListener("scroll", on, true);
    };
  }, [open, place]);

  // Klick daneben und Escape schließen; Escape gibt den Fokus an den Auslöser zurück.
  useEffect(() => {
    if (!open) return;
    const down = (e: PointerEvent) => {
      const t = e.target as Node;
      if (panel.current?.contains(t) || btn.current?.contains(t)) return;
      close();
    };
    const key = (e: KeyboardEvent) => {
      if (e.key !== "Escape") return;
      e.stopPropagation();
      close();
      btn.current?.focus();
    };
    document.addEventListener("pointerdown", down);
    document.addEventListener("keydown", key, true);
    return () => {
      document.removeEventListener("pointerdown", down);
      document.removeEventListener("keydown", key, true);
    };
  }, [open, close]);

  // Beim Öffnen wandert der Fokus ins Fenster; beim Schließen zurück zum Auslöser (nur wenn er im Fenster lag).
  useEffect(() => {
    if (!open) return;
    const p = panel.current;
    const b = btn.current;
    const first = p?.querySelector<HTMLElement>("input, select, button, a[href], [tabindex]:not([tabindex='-1'])");
    (first ?? p)?.focus({ preventScroll: true });
    return () => {
      if (p && p.contains(document.activeElement)) b?.focus({ preventScroll: true });
    };
  }, [open]);

  const t: PopoverTrigger = {
    ref: btn,
    open,
    toggle: () => set(!open),
    close,
    "aria-haspopup": "dialog",
    "aria-expanded": open,
    "aria-controls": open ? id : undefined,
  };
  const style = sheet ? undefined : pos ? { top: pos.top, left: pos.left, width } : undefined;
  return (
    <>
      {trigger(t)}
      {open && typeof document !== "undefined"
        ? createPortal(
            <>
              {sheet ? <div aria-hidden="true" className="fixed inset-0 z-[60] bg-black/40 md:hidden" onClick={close} /> : null}
              <div
                ref={panel}
                id={id}
                role="dialog"
                aria-label={label}
                tabIndex={-1}
                style={pos ? { top: pos.top, left: pos.left, width: Math.min(width, window.innerWidth - 16) } : style}
                className={`fixed z-[60] rounded-sm border border-line bg-surface p-3 text-sm shadow-lg ${
                  sheet ? "max-md:!inset-x-0 max-md:!bottom-0 max-md:!top-auto max-md:!left-0 max-md:!w-auto max-md:max-h-[80vh] max-md:overflow-y-auto max-md:rounded-b-none max-md:p-4 max-md:pb-6" : ""
                }`}
              >
                {typeof children === "function" ? children(close) : children}
              </div>
            </>,
            document.body,
          )
        : null}
    </>
  );
}
