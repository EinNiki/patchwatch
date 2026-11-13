"use client";

import { useId, useRef } from "react";
import { useModal } from "@/components/useModal";
import { Button } from "@/components/Controls";
import { NavIcon } from "@/components/Icons";

/**
 * Modaler Dialog auf Basis von <dialog> (Fokusfalle, Klick auf den Hintergrund und Esc schließen, Scrollsperre, Fokus zurück; siehe `useModal`).
 * `dismissible=false`: Esc schließt nicht (z. B. solange ein Token nur jetzt sichtbar ist).
 */
export function Dialog({
  open,
  title,
  onClose,
  dismissible = true,
  footer,
  footerRef,
  children,
}: {
  open: boolean;
  title: string;
  onClose: () => void;
  dismissible?: boolean;
  /** Feste Fußleiste (z. B. Abbrechen/Speichern): Kopf und Fuß bleiben stehen, nur der Inhalt dazwischen scrollt (genau ein Scrollbereich). */
  footer?: React.ReactNode;
  /** Wie `footer`, aber als leerer Platz, in den der Inhalt per Portal rendert (wenn der Formularzustand unterhalb des Dialogs liegt). */
  footerRef?: (el: HTMLDivElement | null) => void;
  children: React.ReactNode;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  useModal(ref, open, onClose, dismissible);
  return (
    <dialog ref={ref} aria-labelledby={titleId} aria-modal="true" className={`w-full max-w-[40rem] ${footer || footerRef ? "max-h-[calc(100dvh-2rem)] flex-col overflow-hidden open:flex" : ""}`}>
      <div className="mb-3 flex shrink-0 items-start justify-between gap-3">
        <h2 id={titleId} className="text-lg font-semibold">
          {title}
        </h2>
        {/* X-Knopf nur, wo Schließen ohne Datenverlust möglich ist (nicht beim einmalig angezeigten Token/Passwort). */}
        {dismissible ? (
          <Button size="icon" aria-label="Schließen" title="Schließen" onClick={onClose} className="-mr-1 -mt-1">
            <NavIcon name="close" />
          </Button>
        ) : null}
      </div>
      {footer || footerRef ? (
        <>
          <div data-dialog-body className="-mx-1 min-h-0 flex-1 overflow-y-auto px-1">
            {children}
          </div>
          <div ref={footerRef} className="mt-3 shrink-0 border-t border-line pt-3">
            {footer}
          </div>
        </>
      ) : (
        children
      )}
    </dialog>
  );
}
