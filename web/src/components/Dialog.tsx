"use client";

import { useId, useRef } from "react";
import { useModal } from "@/components/useModal";

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
      <h2 id={titleId} className="mb-3 text-lg font-semibold">
        {title}
      </h2>
      {children}
    </dialog>
  );
}
