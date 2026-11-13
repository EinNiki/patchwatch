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
  children,
}: {
  open: boolean;
  title: string;
  onClose: () => void;
  dismissible?: boolean;
  children: React.ReactNode;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  useModal(ref, open, onClose, dismissible);
  return (
    <dialog ref={ref} aria-labelledby={titleId} aria-modal="true" className="w-full max-w-[40rem]">
      <div className="mb-3 flex items-start justify-between gap-3">
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
      {children}
    </dialog>
  );
}
