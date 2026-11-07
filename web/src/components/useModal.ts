"use client";

import { useEffect, useRef } from "react";
import { isOutside, lockScroll } from "@/lib/scrollLock";

// Zuletzt angetippte bedienbare Stelle: Touch-Eingaben setzen den Fokus nicht auf jedem Gerät, das Fenster soll den Fokus
// trotzdem zur auslösenden Schaltfläche zurückgeben.
let lastActuator: HTMLElement | null = null;
let tracking = false;
function track() {
  if (tracking || typeof document === "undefined") return;
  tracking = true;
  document.addEventListener(
    "pointerdown",
    (e) => {
      const t = e.target instanceof Element ? e.target.closest<HTMLElement>("button, a[href], summary, [role=button], input, select, textarea") : null;
      lastActuator = t;
    },
    true,
  );
}

/**
 * Gemeinsames Verhalten aller modalen Fenster (<dialog>): öffnen/schließen nach `open`, Klick auf den Hintergrund
 * schließt (pointerdown statt click, damit eine Textauswahl, die im Fenster beginnt und außerhalb endet, nicht schließt),
 * Escape schließt (native `cancel`), die Seite dahinter scrollt nicht, und der Fokus kehrt zum auslösenden Element zurück.
 * `dismissible=false` (z. B. Token nur einmal sichtbar): weder Hintergrund noch Escape schließen.
 */
export function useModal(ref: React.RefObject<HTMLDialogElement | null>, open: boolean, onClose: () => void, dismissible = true) {
  const opener = useRef<HTMLElement | null>(null);
  const close = useRef(onClose);
  useEffect(() => {
    close.current = onClose;
  });

  useEffect(() => {
    track();
  }, []);

  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) {
      track();
      const active = document.activeElement instanceof HTMLElement && document.activeElement !== document.body ? document.activeElement : null;
      opener.current = active ?? (lastActuator?.isConnected ? lastActuator : null);
      d.showModal();
    }
    if (!open && d.open) {
      // Der Fokus geht erst nach dem Schließen zurück (solange das Fenster modal ist, ist der Hintergrund inert).
      const back = opener.current;
      d.addEventListener(
        "close",
        () => {
          if (back?.isConnected) back.focus({ preventScroll: true });
        },
        { once: true },
      );
      d.close();
    }
  }, [open, ref]);

  // Seite sperren, solange offen; beim Schließen oder Entfernen freigeben und den Fokus zurückgeben.
  useEffect(() => {
    if (!open) return;
    const unlock = lockScroll();
    return unlock;
  }, [open]);

  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    const onDown = (e: PointerEvent) => {
      if (!dismissible || e.target !== d) return;
      if (isOutside(d.getBoundingClientRect(), e.clientX, e.clientY)) close.current();
    };
    const onCancel = (e: Event) => {
      e.preventDefault();
      if (dismissible) close.current();
    };
    d.addEventListener("pointerdown", onDown);
    d.addEventListener("cancel", onCancel);
    return () => {
      d.removeEventListener("pointerdown", onDown);
      d.removeEventListener("cancel", onCancel);
    };
  }, [ref, dismissible]);
}
