"use client";

import { useEffect, useId, useRef } from "react";

/**
 * Modaler Dialog auf Basis von <dialog> (Fokusfalle, Backdrop, Esc).
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
  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) d.showModal();
    if (!open && d.open) d.close();
  }, [open]);
  return (
    <dialog
      ref={ref}
      aria-labelledby={titleId}
      className="w-full max-w-[40rem]"
      onCancel={(e) => {
        e.preventDefault();
        if (dismissible) onClose();
      }}
    >
      <h2 id={titleId} className="mb-3 text-base font-semibold">
        {title}
      </h2>
      {children}
    </dialog>
  );
}
